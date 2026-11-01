#!/usr/bin/env python3
"""Threat model as code for an office vending machine (pytm).

Setup:   python3 -m venv .venv && .venv/bin/pip install pytm
Run:     .venv/bin/python vending_machine_tm.py --list          # threat catalog
         .venv/bin/python vending_machine_tm.py --json tm.json  # machine-readable findings
         .venv/bin/python vending_machine_tm.py --dfd | dot -Tpng -o dfd.png   # needs graphviz
"""
from pytm import TM, Actor, Boundary, Dataflow, Datastore, Server, ExternalEntity

tm = TM("Office Vending Machine")
tm.description = "Cashless + cash vending machine in an office lobby, UPI payments, 4G telemetry."
tm.isOrdered = True
tm.mergeResponses = True

# --- Trust boundaries ---
lobby = Boundary("Office lobby (public to all employees and visitors)")
cabinet = Boundary("Locked machine cabinet")
internet = Boundary("Internet / mobile network")
cloud = Boundary("Operator cloud")

# --- Actors / external entities ---
employee = Actor("Employee or visitor")
employee.inBoundary = lobby

operator = Actor("Route operator (restock, cash collection)")
operator.inBoundary = lobby

psp = ExternalEntity("UPI payment service provider")
psp.inBoundary = internet

# --- Machine internals ---
controller = Server("Machine controller (embedded Linux)")
controller.inBoundary = cabinet
controller.OS = "Embedded Linux"
controller.controls.isHardened = False
controller.controls.sanitizesInput = False
controller.controls.checksInputBounds = False

local_db = Datastore("Local sales and config store")
local_db.inBoundary = cabinet
local_db.isSQL = True
local_db.controls.isEncryptedAtRest = False
local_db.storesPII = False

# --- Cloud ---
backend = Server("Operator backend API")
backend.inBoundary = cloud
backend.controls.isHardened = True
backend.controls.sanitizesInput = True
backend.controls.checksInputBounds = True
backend.controls.implementsAuthenticationScheme = True
backend.controls.implementsNonce = True
backend.controls.hasAccessControl = True

cloud_db = Datastore("Inventory, price and sales DB")
cloud_db.inBoundary = cloud
cloud_db.isSQL = True
cloud_db.controls.isEncryptedAtRest = True

# --- Data flows ---
pick = Dataflow(employee, controller, "Select item, scan UPI QR / tap")
pick.protocol = "Physical"
pick.dstPort = 0

qr = Dataflow(controller, psp, "Create dynamic QR, poll payment status")
qr.protocol = "HTTPS"
qr.dstPort = 443
qr.data = "Order id, amount"
qr.controls.isEncrypted = True
qr.controls.authenticatesDestination = True
qr.controls.authenticatesSource = True   # API key / signed request

cb = Dataflow(psp, controller, "Payment success callback")
cb.protocol = "HTTPS"
cb.dstPort = 443
cb.controls.isEncrypted = True
cb.controls.authenticatesSource = False   # Open question: is the callback signed?

sale = Dataflow(controller, local_db, "Record sale, read price table")
sale.protocol = "Local"   # same device, not a network hop

telemetry = Dataflow(controller, backend, "Telemetry, sales, remote config pull")
telemetry.protocol = "MQTT"
telemetry.dstPort = 8883
telemetry.controls.isEncrypted = True
telemetry.controls.authenticatesSource = True

fw = Dataflow(backend, controller, "Firmware update")
fw.protocol = "HTTPS"
fw.dstPort = 443
fw.controls.isEncrypted = True
fw.controls.authenticatesSource = False   # Open question: is firmware signed and verified?

stock = Dataflow(operator, backend, "Restock report, cash count")
stock.protocol = "HTTPS"
stock.dstPort = 443
stock.controls.isEncrypted = True
stock.controls.authenticatesSource = True   # operator login

svc = Dataflow(operator, controller, "Service mode (keypad/USB/serial)")
svc.protocol = "Physical"
svc.dstPort = 0

store = Dataflow(backend, cloud_db, "Persist inventory and sales")
store.protocol = "TLS"
store.controls.isEncrypted = True
store.controls.authenticatesSource = True

if __name__ == "__main__":
    tm.process()
