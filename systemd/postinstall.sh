#!/bin/sh
systemctl daemon-reload || true
systemctl enable --now tinfoil-sev-shim.service || true
