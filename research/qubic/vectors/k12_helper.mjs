// K12 oracle for cross_check.py.
//
// Reads JSON [{hex, n}] on stdin, writes JSON [hex] on stdout. The
// implementation is the official @qubic.org/crypto package, not a
// reimplementation, so this is a genuine independent check of the K12 layer.
import { k12 } from "@qubic.org/crypto";
import { readFileSync } from "node:fs";

const reqs = JSON.parse(readFileSync(0, "utf8"));
const out = reqs.map(({ hex, n }) => Buffer.from(k12(Buffer.from(hex, "hex"), n)).toString("hex"));
process.stdout.write(JSON.stringify(out));
