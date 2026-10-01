#!/usr/bin/env python3
"""Offline caller binding checks. Never print resource data or parser errors."""
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse

MAX_JSON = 4 << 20
MARKER = "--fixture=p1.8-layered-isolation"


class Rejected(Exception):
    pass


def require(condition, category="binding-rejected"):
    if not condition:
        raise Rejected(category)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "input-rejected")
        result[key] = value
    return result


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON, "input-rejected")
    return json.loads(raw, object_pairs_hook=unique)


def save(path, value):
    # The runner creates private directories. Refuse existing symlinks.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
        stream.write("\n")


def names(cluster, network=None, image=None):
    require(re.fullmatch(r"tn-kind-[a-z]{10}", cluster) is not None, "arguments-rejected")
    if network is not None:
        require(network == cluster + "-net", "arguments-rejected")
    if image is not None:
        require(image == "localhost/tn-source-netprobe:" + cluster, "arguments-rejected")


def endpoint_gateway(value):
    # Podman emits a *string* sentinel for a nil net.IP. JSON null/false/0
    # must not be confused with the typed sentinel (nor may an external GW).
    require(type(value) is str and value in ("", "<nil>"), "gateway-rejected")


def subnet_gateway(subnet):
    # Network inspect uses an omitted/null/empty field, not the endpoint sentinel.
    require("gateway" not in subnet or subnet["gateway"] is None or
            type(subnet["gateway"]) is str and subnet["gateway"] == "", "gateway-rejected")


def image_hash(value):
    require(type(value) is str and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) is not None,
            "image-rejected")
    return "sha256:" + value.removeprefix("sha256:")


def image_binding(local, cri, status, image):
    require(len(local) == 1, "image-rejected")
    require(cri["id"] == image_hash(local[0]["Id"]), "image-rejected")
    require(image in cri["repoTags"], "image-rejected")
    digests = cri["repoDigests"]
    require(type(digests) is list and 0 < len(digests) <= 8, "image-rejected")
    repo = image.rsplit(":", 1)[0]
    for digest in digests:
        require(type(digest) is str, "image-rejected")
        # ctr can expose its date-named Docker archive import alias instead of
        # the tagged repository. Content identity still requires the exact
        # locally built config digest, expected tag and Pod imageID above/below.
        if digest.startswith(repo + "@"):
            value = digest.removeprefix(repo + "@")
        else:
            match = re.fullmatch(r"docker\.io/library/import-[0-9]{4}-[0-9]{2}-[0-9]{2}@(sha256:[0-9a-f]{64})", digest)
            require(match is not None, "image-rejected")
            value = match.group(1)
        require(value.startswith("sha256:") and image_hash(value) == value, "image-rejected")
    require(status["imageID"] in digests, "image-rejected")


def kube_binding(value, cluster):
    ctx = "kind-" + cluster
    require(value["current-context"] == ctx and len(value["clusters"]) == len(value["contexts"]) == len(value["users"]) == 1)
    c, context, user = value["clusters"][0], value["contexts"][0], value["users"][0]
    require(c["name"] == context["name"] == context["context"]["cluster"] == context["context"]["user"] == user["name"] == ctx)
    require(set(c["cluster"]) == {"server", "certificate-authority-data"})
    require(set(user["user"]) == {"client-certificate-data", "client-key-data"})
    require(all(type(v) is str and v for v in user["user"].values()))
    require(type(c["cluster"]["certificate-authority-data"]) is str and c["cluster"]["certificate-authority-data"])
    require(set(context["context"]) == {"cluster", "user"})
    url = urllib.parse.urlsplit(c["cluster"]["server"])
    require(url.scheme == "https" and url.hostname == "127.0.0.1" and url.username is None and
            url.password is None and not url.path and not url.query and not url.fragment and
            url.port is not None and 1024 <= url.port <= 65535)
    return url.port


def network_binding(value, cluster, network):
    require(len(value) == 1, "network-rejected")
    net = value[0]
    require(net["name"] == network and net["driver"] == "bridge" and net["internal"] is True and
            net["dns_enabled"] is False and net["ipv6_enabled"] is False, "network-rejected")
    require(net["labels"] == {"netproof-owner": cluster} and net["options"]["isolate"] == "true", "network-rejected")
    require(type(net["id"]) is str and bool(net["id"]), "network-rejected")
    require(len(net["subnets"]) == 1, "network-rejected")
    subnet_gateway(net["subnets"][0])
    prefix = ipaddress.ip_network(net["subnets"][0]["subnet"])
    require(prefix.version == 4 and prefix.prefixlen == 24 and prefix.is_private, "network-rejected")
    return net


def stable(out):
    before, after = load(out / "pod-before.json"), load(out / "pod-after.json")
    require(before["metadata"]["uid"] == after["metadata"]["uid"] and before["spec"] == after["spec"] and
            before["status"] == after["status"], "binding-churn")
    before, after = load(out / "nodes-before.json")["items"], load(out / "nodes-after.json")["items"]
    require(len(before) == len(after) == 1, "binding-churn")
    require(before[0]["metadata"]["uid"] == after[0]["metadata"]["uid"] and before[0]["spec"] == after[0]["spec"] and
            before[0]["status"]["addresses"] == after[0]["status"]["addresses"], "binding-churn")
    before, after = load(out / "node-container-before.json"), load(out / "node-container-after.json")
    require(len(before) == len(after) == 1 and before[0]["Id"] == after[0]["Id"] and
            before[0]["NetworkSettings"] == after[0]["NetworkSettings"] and
            before[0]["Config"]["Labels"] == after[0]["Config"]["Labels"], "binding-churn")


def pod_binding(p, node, cluster, image, cidr):
    require(p["metadata"]["name"] == "owned-netproof" and p["metadata"]["namespace"] == "default")
    require(p["metadata"]["labels"] == {"netproof-owner": cluster} and
            not p["metadata"].get("ownerReferences") and not p["metadata"].get("deletionTimestamp"))
    spec = p["spec"]
    require(spec["nodeName"] == node and not spec.get("hostNetwork", False) and not spec.get("hostPID", False) and
            not spec.get("hostIPC", False) and spec["automountServiceAccountToken"] is False and
            spec["enableServiceLinks"] is False and spec["restartPolicy"] == "Never")
    require(not spec.get("volumes") and not spec.get("initContainers") and not spec.get("ephemeralContainers") and len(spec["containers"]) == 1)
    sc = spec["securityContext"]
    require(sc["runAsNonRoot"] is True and type(sc["runAsUser"]) is int and sc["runAsUser"] == sc["runAsGroup"] == 65532 and
            sc["seccompProfile"] == {"type": "RuntimeDefault"})
    pc = spec["containers"][0]
    require(pc["name"] == "holder" and pc["image"] == image and pc["imagePullPolicy"] == "Never" and
            pc["command"] == ["/hold"] and pc["args"] == [MARKER] and not pc.get("volumeMounts") and
            not pc.get("env") and not pc.get("envFrom") and not pc.get("ports") and not pc.get("lifecycle"))
    sec = pc["securityContext"]
    require(sec == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}})
    require(pc["resources"]["limits"] == {"cpu": "100m", "memory": "32Mi"})
    status = p["status"]
    require(status["phase"] == "Running" and status["podIPs"] == [{"ip": status["podIP"]}])
    require(ipaddress.ip_address(status["podIP"]) in ipaddress.ip_network(cidr))
    cs = status["containerStatuses"]
    require(len(cs) == 1 and cs[0]["name"] == "holder" and cs[0]["ready"] is True and cs[0]["restartCount"] == 0)
    require(set(cs[0]["state"]) == {"running"} and bool(cs[0]["containerID"]))
    return status


def check(out, cluster, network, image):
    names(cluster, network, image)
    stable(out)
    port_number = kube_binding(load(out / "kubeconfig-binding.json"), cluster)
    uid = (out / "cluster-uid.txt").read_text()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uid) is not None and
            uid == (out / "cluster-uid-after.txt").read_text())
    n = load(out / "nodes-before.json")["items"][0]
    a = load(out / "nodes-after.json")["items"][0]
    require(n["metadata"]["name"] == a["metadata"]["name"] == cluster + "-control-plane")
    require(any(c["type"] == "Ready" and c["status"] == "True" for c in a["status"]["conditions"]))
    ips = [x["address"] for x in n["status"]["addresses"] if x["type"] == "InternalIP"]
    require(len(ips) == 1)
    cidr = n["spec"]["podCIDR"]
    require(n["spec"]["podCIDRs"] == [cidr])
    b = load(out / "node-container-before.json")[0]
    require(b["Name"] == cluster + "-control-plane")
    require(b["Config"]["Labels"]["io.x-k8s.kind.cluster"] == cluster and b["Config"]["Labels"]["io.x-k8s.kind.role"] == "control-plane")
    require(set(b["NetworkSettings"]["Networks"]) == {network})
    ports = b["NetworkSettings"]["Ports"]
    require(set(ports) == {"6443/tcp"} and len(ports["6443/tcp"]) == 1)
    port = ports["6443/tcp"][0]
    require(port["HostIp"] == "127.0.0.1" and str(port_number) == port["HostPort"])
    owned = load(out / "owned-containers.json")
    require(len(owned) == 1 and owned[0]["Id"] == b["Id"])
    netb = network_binding(load(out / "network-before.json"), cluster, network)
    net = network_binding(load(out / "network-after.json"), cluster, network)
    require(netb["id"] == net["id"] and netb["subnets"] == net["subnets"])
    require(set(net["containers"]) == {b["Id"]})
    outer = net["subnets"][0]["subnet"]
    endpoint = b["NetworkSettings"]["Networks"][network]
    endpoint_gateway(endpoint.get("Gateway"))
    require(endpoint["NetworkID"] == net["id"] and endpoint["IPAddress"] == ips[0] and
            endpoint["IPPrefixLen"] == ipaddress.ip_network(outer).prefixlen)
    interfaces = net["containers"][b["Id"]]["interfaces"]
    require(len(interfaces) == 1)
    ep = next(iter(interfaces.values()))
    require(len(ep["subnets"]) == 1 and ep["subnets"][0]["ipnet"] == ips[0] + "/" + str(endpoint["IPPrefixLen"]))
    subnet_gateway(ep["subnets"][0])
    p = load(out / "pod-before.json")
    status = pod_binding(p, n["metadata"]["name"], cluster, image, cidr)
    image_binding(load(out / "probe-image.json"), load(out / "probe-cri-image.json")["status"], status["containerStatuses"][0], image)
    pods = load(out / "cluster-pods.json")["items"]
    require(sum(x["metadata"]["uid"] == p["metadata"]["uid"] for x in pods) == 1)
    allowed = {"etcd", "kube-apiserver", "kube-controller-manager", "kube-scheduler"}
    for x in pods:
        if x["metadata"]["uid"] == p["metadata"]["uid"]:
            require(x["spec"] == p["spec"] and x["status"] == p["status"], "binding-churn")
            continue
        name, namespace = x["metadata"]["name"], x["metadata"]["namespace"]
        require((namespace == "kube-system" and (any(name == v + "-" + cluster + "-control-plane" for v in allowed) or
                name.startswith(("coredns-", "kindnet-", "kube-proxy-")))) or
                (namespace == "local-path-storage" and name.startswith("local-path-provisioner-")))
    deps = load(out / "deployments.json")["items"]
    require(len(deps) == 2 and {(x["metadata"]["namespace"], x["metadata"]["name"]) for x in deps} ==
            {("kube-system", "coredns"), ("local-path-storage", "local-path-provisioner")})
    for resource in ("statefulsets", "jobs", "cronjobs"):
        require(not load(out / (resource + ".json"))["items"])
    ds = load(out / "daemonsets.json")["items"]
    require(len(ds) == 2 and {(x["metadata"]["namespace"], x["metadata"]["name"]) for x in ds} ==
            {("kube-system", "kindnet"), ("kube-system", "kube-proxy")})
    require(re.search(r"\bforward\b", load(out / "coredns-after.json")["data"]["Corefile"]) is None)
    d = next(x for x in deps if x["metadata"]["name"] == "coredns")
    require(d["status"]["observedGeneration"] == d["metadata"]["generation"] and
            d["status"]["readyReplicas"] == d["spec"]["replicas"] == d["status"]["updatedReplicas"])
    require("kubectl.kubernetes.io/restartedAt" in d["spec"]["template"]["metadata"]["annotations"])
    times = load(out / "capture-times.json")
    require(type(times["start"]) is int and type(times["end"]) is int and
            0 <= times["end"] - times["start"] <= 12 and 0 <= time.time() - times["end"] <= 60, "freshness-rejected")
    # This is the policy-free owned-netproof control, not a policy-selected
    # startup Pod. Both its dials remain strict, like the authoritative node.
    node_dials, pod_dials = (load(out / f)["dials"] for f in ("node-capture.json", "pod-capture.json"))
    require(node_dials == {"ipv4": "ENETUNREACH", "ipv6": "ENETUNREACH"}, "dial-rejected")
    require(pod_dials == {"ipv4": "ENETUNREACH", "ipv6": "ENETUNREACH"}, "dial-rejected")
    save(out / "binding.json", {"OuterCIDR": outer, "NodeIP": ips[0], "PodCIDR": cidr, "PodIP": status["podIP"]})
    return {"callerGatePassed": True, "exactENETUNREACHCount": 2 + sum(v == "ENETUNREACH" for v in pod_dials.values())}


def patch(source, destination):
    lines = load(source)["data"]["Corefile"].splitlines(keepends=True)
    indices = [i for i, line in enumerate(lines) if line.strip().startswith("forward ")]
    require(len(indices) == 1, "coredns-rejected")
    i = indices[0]
    j, depth = i + 1, lines[i].count("{") - lines[i].count("}")
    while depth > 0 and j < len(lines):
        depth += lines[j].count("{") - lines[j].count("}")
        j += 1
    text = "".join(lines[:i] + lines[j:])
    require(depth == 0 and re.search(r"\bforward\b", text) is None, "coredns-rejected")
    save(destination, {"data": {"Corefile": text}})


def scope():
    lines = Path("/proc/self/cgroup").read_text().splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::"), "delegation-rejected")
    path = lines[0][3:]
    require(f"/user@{os.getuid()}.service/" in path, "delegation-rejected")
    name = path.rsplit("/", 1)[-1]
    require(re.fullmatch(r"[a-zA-Z0-9_.@-]+\.scope", name) is not None, "delegation-rejected")
    return name, path


def main(args):
    os.umask(0o077)
    try:
        require(bool(args), "arguments-rejected")
        mode, *args = args
        if mode == "check" and len(args) == 4:
            print(json.dumps(check(Path(args[0]), *args[1:])))
        elif mode == "network" and len(args) == 3:
            names(args[1], args[2])
            network_binding(load(args[0]), args[1], args[2])
        elif mode == "kube" and len(args) == 2:
            names(args[1])
            kube_binding(load(args[0]), args[1])
        elif mode == "stable" and len(args) == 1:
            stable(Path(args[0]))
        elif mode == "patch" and len(args) == 2:
            patch(*args)
        elif mode == "render" and len(args) == 3:
            names(args[2])
            value = load(args[0])
            require(value["metadata"]["labels"]["netproof-owner"] == "@CLUSTER@" and
                    value["spec"]["containers"][0]["image"] == "@IMAGE@", "template-rejected")
            value["metadata"]["labels"]["netproof-owner"] = args[2]
            value["spec"]["containers"][0]["image"] = "localhost/tn-source-netprobe:" + args[2]
            save(args[1], value)
        elif mode == "scope" and not args:
            print(scope()[0])
        elif mode == "delegation" and len(args) == 1:
            props = dict(line.split("=", 1) for line in Path(args[0]).read_text().splitlines())
            require(props.get("Delegate") == "yes" and props.get("Transient") == "yes" and
                    props.get("ControlGroup") == scope()[1], "delegation-rejected")
        elif mode == "cleanup-containers" and len(args) == 2:
            names(args[1])
            value = load(args[0])
            require(type(value) is list and len(value) <= 1, "cleanup-owner-rejected")
            for container in value:
                require(container["Labels"]["io.x-k8s.kind.cluster"] == args[1] and
                        container["Labels"]["io.x-k8s.kind.role"] == "control-plane" and
                        container["Names"] == [args[1] + "-control-plane"] and
                        re.fullmatch(r"[0-9a-f]{64}", container["Id"]) is not None, "cleanup-owner-rejected")
            for container in value:
                print(container["Id"])
        elif mode == "cleanup-network" and len(args) == 3:
            names(args[1], args[2])
            value = load(args[0])
            require(len(value) == 1 and value[0]["name"] == args[2] and
                    value[0]["labels"] == {"netproof-owner": args[1]} and
                    not value[0].get("containers"), "cleanup-owner-rejected")
        elif mode in ("cleanup-image", "cleanup-agent-image") and len(args) == 3:
            names(args[1])
            repo = "localhost/tn-source-netprobe:" if mode == "cleanup-image" else "localhost/tailnet-operator-e2e:"
            require(args[2] == repo + args[1], "arguments-rejected")
            value = load(args[0])
            require(len(value) == 1 and value[0]["Labels"].get("netproof-owner") == args[1] and
                    value[0]["RepoTags"] == [args[2]], "cleanup-owner-rejected")
            image_hash(value[0]["Id"])
        elif mode == "empty" and args:
            require(all(load(path) == [] for path in args), "absence-rejected")
        else:
            raise Rejected("arguments-rejected")
        return 0
    except Rejected as err:
        print(str(err), file=sys.stderr)  # Only fixed categories defined here.
    except Exception:
        print("input-rejected", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
