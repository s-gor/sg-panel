# Bundled SG Client GeoFiles

This directory contains the linked `geoip.dat` / `geosite.dat` pair copied from the verified SG Client 086 offline runtime supplied for this SG-Panel work.

The files are data assets only. SG-Panel and SG-Client codebases remain independent.

## Integrity manifest

| File | Size | SHA-256 | Categories |
|---|---:|---|---:|
| `geoip.dat` | 19,435,989 bytes | `c0f37cacaca04fcf273d6fc740e236748b2a7a082056b162bf7ce95db8af6efa` | 266 |
| `geosite.dat` | 71,804,643 bytes | `8bc708286ac3160003d9eba7290841f931e3ef41a05d92555a07b513a7a08163` | 1,506 |

`xpanel.service` pins these hashes. A damaged or accidentally replaced bundled file is rejected before it can be staged or applied.

External sources selected in the UI are downloaded and validated independently; they are not expected to match this manifest.
