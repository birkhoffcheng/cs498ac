"""
# Problem 2: Garbled Circuit Generator (30 points)
"""

import circuit
from circuit import BooleanCircuit
import json
from util import specialDecryption, specialEncryption, generate_key
import os
import random


def shuffle(a):
    assert type(a) is list
    random.shuffle(a)

"""
## Problem 2: Garbled Circuit Generator (15 points)
"""

class GarbledCircuitGenerator(BooleanCircuit):
    def __init__(self, from_json=None):
        # The superclass constructor initializes the gates and topological sorting
        super(GarbledCircuitGenerator,self).__init__(from_json=from_json)

    def garble(self):

        # Generate new wire labels
        self.wire_labels = {} # maps wire id to {"0":label0 ,"1": label1}

        # TODO: your code goes here
        for wire in self.wires:
            k0 = generate_key().hex()
            k1 = generate_key().hex()
            self.wire_labels[wire] = [k0, k1]

        # Generate garble tables
        self.garble_table = {}

        # TODO: your code goes here
        for gid in self.sorted_gates:
            gate = self.gates[gid]
            in0 = gate["inp"][0]
            in1 = gate["inp"][1]
            out = gate["out"][0]
            table = gate["table"]
            garble_table = []
            for i in range(len(table)):
                in0_value = (i >> 1) & 1
                in1_value = i & 1
                in0_key = bytes.fromhex(self.wire_labels[in0][in0_value])
                in1_key = bytes.fromhex(self.wire_labels[in1][in1_value])
                out_key = bytes.fromhex(self.wire_labels[out][table[i]])
                cip_inner = specialEncryption(in1_key, out_key)
                cip_outer = specialEncryption(in0_key, cip_inner)
                garble_table.append(cip_outer.hex())

            shuffle(garble_table)
            self.garble_table[gid] = garble_table

    def output(self, outfile, inputs=None, debug=True):
        # Save as a JSON file, with wire lables for debugging
        obj = {}
        gates = {}
        for gid,gate in self.gates.items():
            gates[gid] = gate.copy() # Copy the gate object directly
            gates[gid]["garble_table"] = self.garble_table[gid]
        obj["gates"] = gates

        # Output wire labels in debug mode
        if debug:
            obj["wire_labels"] = self.wire_labels

        if inputs is not None:
            print('Input available')
            assert len(inputs) == len(self.input_wires)
            input_labels = {}
            for wid,v in inputs.items():
                assert v in (0,1)
                input_labels[wid] = self.wire_labels[wid][v]
                obj["inputs"] = input_labels

        with open(outfile,"w") as f:
            json.dump(obj, f, indent=4)
        print('Wrote garbled circuit', outfile)

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("usage: python generator.py <circuit.json> <outfile.json>")
        sys.exit(1)

    filename = sys.argv[1]
    obj = json.load(open(filename))

    # Circuit
    c = GarbledCircuitGenerator(from_json=obj)
    print('Circuit loaded: %d gates, %d input wires, %d output_wires, %d total' \
        % (len(c.gates), len(c.input_wires), len(c.output_wires), len(c.wires)))

    # Generate the circuit
    c.garble()

    # Load the inputs
    inputs = obj["inputs"]

    # Write the output
    outfile = sys.argv[2]
    c.output(outfile, inputs)
