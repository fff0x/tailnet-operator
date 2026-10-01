#!/usr/bin/env python3
"""Pure synthetic/offline negative checks; no runtime or resource output."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("network_gate", Path(__file__).with_name("network-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CLUSTER = "tn-kind-abcdefghij"
NETWORK = CLUSTER + "-net"
IMAGE = "localhost/tn-source-netprobe:" + CLUSTER
HASH = "a" * 64
DIGEST = "localhost/tn-source-netprobe@sha256:" + "b" * 64


def evidence():
    pod = gate.load(Path(__file__).with_name("netprobe-pod.json"))
    pod["metadata"].update(uid="holder-uid", labels={"netproof-owner": CLUSTER})
    pod["spec"]["containers"][0]["image"] = IMAGE
    pod["spec"]["nodeName"] = CLUSTER + "-control-plane"
    pod["status"] = {"phase": "Running", "podIP": "10.244.0.5", "podIPs": [{"ip": "10.244.0.5"}],
                     "containerStatuses": [{"name": "holder", "ready": True, "restartCount": 0,
                                            "state": {"running": {}}, "containerID": "containerd://fixture", "imageID": DIGEST}]}
    node = {"metadata": {"uid": "node-uid", "name": CLUSTER + "-control-plane"},
            "spec": {"podCIDR": "10.244.0.0/24", "podCIDRs": ["10.244.0.0/24"]},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.89.0.2"}],
                       "conditions": [{"type": "Ready", "status": "True"}]}}
    container = {"Id": HASH, "Name": CLUSTER + "-control-plane", "Config": {"Labels": {
        "io.x-k8s.kind.cluster": CLUSTER, "io.x-k8s.kind.role": "control-plane"}},
        "NetworkSettings": {"Networks": {NETWORK: {"Gateway": "<nil>", "NetworkID": "network-id", "IPAddress": "10.89.0.2", "IPPrefixLen": 24}},
                            "Ports": {"6443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "45678"}]}}}
    network = {"id": "network-id", "name": NETWORK, "driver": "bridge", "internal": True,
               "dns_enabled": False, "ipv6_enabled": False, "options": {"isolate": "true"},
               "labels": {"netproof-owner": CLUSTER}, "subnets": [{"subnet": "10.89.0.0/24"}],
               "containers": {HASH: {"interfaces": {"eth0": {"subnets": [{"ipnet": "10.89.0.2/24"}]}}}}}
    ctx = "kind-" + CLUSTER
    kube = {"current-context": ctx, "clusters": [{"name": ctx, "cluster": {"server": "https://127.0.0.1:45678", "certificate-authority-data": "DATA+OMITTED"}}],
            "contexts": [{"name": ctx, "context": {"cluster": ctx, "user": ctx}}],
            "users": [{"name": ctx, "user": {"client-certificate-data": "DATA+OMITTED", "client-key-data": "DATA+OMITTED"}}]}
    deps = [{"metadata": {"namespace": "kube-system", "name": "coredns", "generation": 2},
             "status": {"observedGeneration": 2, "readyReplicas": 2, "updatedReplicas": 2},
             "spec": {"replicas": 2, "template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": "fixture"}}}}},
            {"metadata": {"namespace": "local-path-storage", "name": "local-path-provisioner"}}]
    value = {"kubeconfig-binding.json": kube, "nodes-before.json": {"items": [node]}, "nodes-after.json": {"items": [node]},
             "node-container-before.json": [container], "node-container-after.json": [container],
             "network-before.json": [network], "network-after.json": [network],
             "pod-before.json": pod, "pod-after.json": pod, "cluster-pods.json": {"items": [pod]},
             "owned-containers.json": [{"Id": HASH}], "probe-image.json": [{"Id": HASH}],
             "probe-cri-image.json": {"status": {"id": "sha256:" + HASH, "repoTags": [IMAGE], "repoDigests": [DIGEST]}},
             "deployments.json": {"items": deps}, "daemonsets.json": {"items": [
                 {"metadata": {"namespace": "kube-system", "name": name}} for name in ("kindnet", "kube-proxy")]},
             "statefulsets.json": {"items": []}, "jobs.json": {"items": []}, "cronjobs.json": {"items": []},
             "coredns-after.json": {"data": {"Corefile": ".:53 {\n kubernetes cluster.local\n}"}},
             "capture-times.json": {"start": int(time.time()) - 1, "end": int(time.time())},
             "node-capture.json": {"dials": {"ipv4": "ENETUNREACH", "ipv6": "ENETUNREACH"}},
             "pod-capture.json": {"dials": {"ipv4": "ENETUNREACH", "ipv6": "ENETUNREACH"}}}
    # Break shared fixture references so mutations only change one file.
    return json.loads(json.dumps(value))


class GateTests(unittest.TestCase):
    def test_gateway(self):
        for value in ("", "<nil>"):
            gate.endpoint_gateway(value)
        for value in (None, False, 0, [], {}, "nil", "0.0.0.0", "10.89.0.1", "192.0.2.1", "::"):
            with self.assertRaises(gate.Rejected):
                gate.endpoint_gateway(value)
        for value in (False, 0, "<nil>", "10.89.0.1", "192.0.2.1"):
            with self.assertRaises(gate.Rejected):
                gate.subnet_gateway({"gateway": value})

    def test_image_ids(self):
        for value in (HASH, "sha256:" + HASH):
            self.assertEqual(gate.image_hash(value), "sha256:" + HASH)
        for value in (None, False, "", HASH.upper(), "sha512:" + HASH, HASH[:-1], HASH + "\n", "sha256:sha256:" + HASH):
            with self.assertRaises(gate.Rejected):
                gate.image_hash(value)
        local = [{"Id": HASH}]
        cri = {"id": "sha256:" + HASH, "repoTags": [IMAGE], "repoDigests": [DIGEST]}
        gate.image_binding(local, cri, {"imageID": DIGEST}, IMAGE)
        for key, value in (("id", HASH), ("id", "sha256:" + "c" * 64), ("repoTags", []),
                           ("repoDigests", ["foreign@sha256:" + HASH]), ("repoDigests", ["sha256:bad"])):
            bad = copy.deepcopy(cri)
            bad[key] = value
            with self.assertRaises(gate.Rejected):
                gate.image_binding(local, bad, {"imageID": DIGEST}, IMAGE)
        with self.assertRaises(gate.Rejected):
            gate.image_binding(local, cri, {"imageID": "sha256:" + HASH}, IMAGE)
        imported = copy.deepcopy(cri)
        alias = "docker.io/library/import-2026-10-01@sha256:" + "b" * 64
        imported["repoDigests"] = [alias]
        gate.image_binding(local, imported, {"imageID": alias}, IMAGE)
        for altered in ("docker.io/library/foreign@sha256:" + HASH,
                        "docker.io/library/import-2026-10-01@sha256:" + HASH[:-1]):
            imported["repoDigests"] = [altered]
            with self.assertRaises(gate.Rejected):
                gate.image_binding(local, imported, {"imageID": altered}, IMAGE)
        imported["repoDigests"] = [alias]
        imported["id"] = "sha256:" + "c" * 64
        with self.assertRaises(gate.Rejected):
            gate.image_binding(local, imported, {"imageID": alias}, IMAGE)
        bare = copy.deepcopy(cri)
        bare["repoDigests"] = ["sha256:" + HASH]
        with self.assertRaises(gate.Rejected):
            gate.image_binding(local, bare, {"imageID": "sha256:" + HASH}, IMAGE)

    def check_fixture(self, values, success, count=4):
        with tempfile.TemporaryDirectory(prefix="projection-gate-test-") as tmp:
            out = Path(tmp)
            for name, value in values.items():
                gate.save(out / name, value)
            for name in ("cluster-uid.txt", "cluster-uid-after.txt"):
                (out / name).write_text("12345678-1234-1234-1234-123456789abc")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = gate.main(["check", str(out), CLUSTER, NETWORK, IMAGE])
            self.assertEqual(rc, 0 if success else 2)
            if success:
                self.assertEqual(json.loads(stdout.getvalue())["exactENETUNREACHCount"], count)
                self.assertEqual(gate.load(out / "binding.json")["NodeIP"], "10.89.0.2")
            else:
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(stderr.getvalue().strip(), {"binding-rejected", "binding-churn", "input-rejected",
                    "gateway-rejected", "image-rejected", "freshness-rejected", "dial-rejected", "network-rejected"})
                self.assertFalse((out / "binding.json").exists())

    def test_full_binding_and_negative_mutations(self):
        self.check_fixture(evidence(), True)
        # The policy-free baseline control must still deliver ENETUNREACH.
        timeout = evidence()
        timeout["pod-capture.json"]["dials"]["ipv4"] = "timeout"
        self.check_fixture(timeout, False)
        mutations = [
            ("kubeconfig-binding.json", ["clusters", 0, "cluster", "server"], "https://192.0.2.1:45678"),
            ("kubeconfig-binding.json", ["users", 0, "user", "exec"], {"command": "private-input"}),
            ("nodes-after.json", ["items", 0, "metadata", "uid"], "changed"),
            ("pod-after.json", ["status", "phase"], "Succeeded"),
            ("network-after.json", [0, "internal"], False),
            ("network-after.json", [0, "labels", "netproof-owner"], "foreign"),
            ("node-container-before.json", [0, "NetworkSettings", "Networks", NETWORK, "Gateway"], "192.0.2.1"),
            ("owned-containers.json", [0, "Id"], "foreign"),
            ("probe-cri-image.json", ["status", "id"], "sha256:invalid"),
            ("capture-times.json", ["end"], int(time.time()) - 100),
            ("capture-times.json", ["end"], int(time.time()) + 100),
            ("node-capture.json", ["dials", "ipv6"], "EAFNOSUPPORT"),
            ("node-capture.json", ["dials", "ipv4"], "timeout"),
            ("pod-capture.json", ["dials", "ipv4"], "refused"),
            ("pod-capture.json", ["dials", "ipv6"], "timeout"),
            ("coredns-after.json", ["data", "Corefile"], "forward . /etc/resolv.conf"),
            ("deployments.json", ["items", 0, "status", "readyReplicas"], 0),
        ]
        for filename, path, value in mutations:
            values = evidence()
            obj = values[filename]
            for key in path[:-1]:
                obj = obj[key]
            obj[path[-1]] = value
            self.check_fixture(values, False)
        for path, value in ((["containers", 0, "args"], []), (["securityContext", "runAsUser"], 0),
                            (["containers", 0, "env"], [{"name": "UNSAFE", "value": "private-input"}]),
                            (["hostNetwork"], True), (["volumes"], [{"hostPath": {"path": "/"}}])):
            values = evidence()
            for filename in ("pod-before.json", "pod-after.json"):
                obj = values[filename]["spec"]
                for key in path[:-1]:
                    obj = obj[key]
                obj[path[-1]] = value
            self.check_fixture(values, False)

    def test_cleanup_boundaries(self):
        cases = [
            ("cleanup-containers", [CLUSTER], [{"Id": HASH, "Names": [CLUSTER + "-control-plane"], "Labels": {
                "io.x-k8s.kind.cluster": CLUSTER, "io.x-k8s.kind.role": "control-plane"}}]),
            ("cleanup-network", [CLUSTER, NETWORK], [{"name": NETWORK, "labels": {"netproof-owner": CLUSTER}, "containers": {}}]),
            ("cleanup-image", [CLUSTER, IMAGE], [{"Id": HASH, "Labels": {"netproof-owner": CLUSTER, "io.buildah.version": "fixture"}, "RepoTags": [IMAGE]}]),
            ("cleanup-agent-image", [CLUSTER, "localhost/tailnet-operator-e2e:" + CLUSTER], [{"Id": HASH, "Labels": {"netproof-owner": CLUSTER}, "RepoTags": ["localhost/tailnet-operator-e2e:" + CLUSTER]}]),
        ]
        with tempfile.TemporaryDirectory(prefix="projection-gate-test-") as tmp:
            path = Path(tmp) / "input.json"
            for mode, args, value in cases:
                gate.save(path, value)
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(gate.main([mode, str(path)] + args), 0)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(stdout.getvalue(), HASH + "\n" if mode == "cleanup-containers" else "")
                bad = copy.deepcopy(value)
                if mode == "cleanup-containers":
                    bad[0]["Names"] = ["foreign"]
                elif mode == "cleanup-network":
                    bad[0]["containers"] = {"foreign": {}}
                else:
                    bad[0]["RepoTags"].append("localhost/shared:keep")
                gate.save(path, bad)
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(gate.main([mode, str(path)] + args), 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "cleanup-owner-rejected\n")

    def test_parser_and_cleanup_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="projection-gate-test-") as tmp:
            path = Path(tmp) / "input.json"
            for text in ('{"x":1,"x":2}', 'private-input', ' ' * (gate.MAX_JSON + 1)):
                path.write_text(text)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(gate.main(["empty", str(path)]), 2)
                self.assertEqual(stderr.getvalue(), "input-rejected\n")
            gate.save(path, [{"Id": HASH, "Names": [CLUSTER + "-control-plane"], "Labels": {
                "io.x-k8s.kind.cluster": "foreign", "io.x-k8s.kind.role": "control-plane"}}])
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(gate.main(["cleanup-containers", str(path), CLUSTER]), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "cleanup-owner-rejected\n")


if __name__ == "__main__":
    unittest.main()
