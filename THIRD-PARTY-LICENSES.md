# Third-party licenses

This document is a **concise inventory of the third-party components reviewed for this project**. It is an engineering
summary, **not a complete legal audit**, and it is not legal advice.

## What the Apache-2.0 license covers

The [LICENSE](LICENSE) (Apache License, Version 2.0) applies to **AgentOps-owned source code** in this repository. It
does not relicense any third-party library, container image, model weight or dataset, and it does not replace their
licenses. Each third-party item below remains under its own terms.

## How third-party material relates to this repository

1. **AgentOps-owned source code.** Everything in this repository, under the LICENSE.
2. **Third-party Python dependencies.** Not included in this repository. They are declared in `requirements.txt` files and
   installed separately by the user (`pip install`).
3. **Docker images built locally.** The Dockerfiles under `docker/` install packages when a user builds an image on their
   own machine. This repository publishes no image.
4. **Model weights downloaded separately.** The embedding model is not included. It is fetched only by an explicit,
   separate command documented in `incident-retrieval/sentence_transformer_backend.py`.
5. **Future redistribution.** If anyone later publishes a built image, a dependency bundle or model weights, the
   obligations in the table below apply to that artifact and must be reviewed at that time.

## Inventory

Versions are those declared in the repository's requirements files, or, where noted, the version whose metadata was
checked. Licenses are as declared in the official package metadata or model card on the review date (2026-11-08).

| Component | Version | License identified | Official source | In this repository? | Material considerations |
|---|---|---|---|---|---|
| psycopg | declared `>=3.1,<4.0`; 3.3.8 checked | LGPL-3.0-only | https://pypi.org/pypi/psycopg/3.3.8/json ; https://raw.githubusercontent.com/psycopg/psycopg/master/LICENSE.txt | No, installed separately | LGPL obligations must be reviewed if the library is redistributed (license text, source availability, replaceability) |
| psycopg-binary | 3.3.8 checked (installed via `psycopg[binary]`) | LGPL-3.0-only | https://pypi.org/pypi/psycopg-binary/3.3.8/json ; https://www.psycopg.org/psycopg3/docs/basic/install.html | No, installed separately | As for psycopg. The wheel is described by its project as self-contained and bundles native libraries; **those bundled libraries were not fully audited** |
| psycopg2-binary | 2.9.13 checked (transitive, required by dbt-postgres) | "LGPL with exceptions" (PyPI classifier: LGPL) | https://pypi.org/pypi/psycopg2-binary/json ; requirement listed at https://pypi.org/pypi/dbt-postgres/1.11.0/json | No, installed separately; present only in the locally built dbt bootstrap image | LGPL obligations must be reviewed if affected images or bundles are redistributed. Its exceptions and bundled libraries were not audited |
| dbt-core | 1.12.5 | Apache-2.0 | https://pypi.org/pypi/dbt-core/1.12.5/json ; https://raw.githubusercontent.com/dbt-labs/dbt-core/main/LICENSE | No, installed separately | Keep license and any NOTICE when redistributing |
| dbt-postgres | 1.11.0 | Apache-2.0 | https://pypi.org/pypi/dbt-postgres/1.11.0/json ; https://raw.githubusercontent.com/dbt-labs/dbt-adapters/main/LICENSE | No, installed separately | As for dbt-core |
| sentence-transformers | 6.1.0 | Apache-2.0 | https://pypi.org/pypi/sentence-transformers/6.1.0/json ; https://raw.githubusercontent.com/UKPLab/sentence-transformers/main/LICENSE | No, installed separately | The package ships a `NOTICE.txt`; **the NOTICE must be preserved when applicable** (for example when redistributing the package) |
| torch | 2.14.1 | PyPI metadata lists a composite expression: Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT. The project's own LICENSE is a BSD-3-style text | https://pypi.org/pypi/torch/2.14.1/json ; https://raw.githubusercontent.com/pytorch/pytorch/main/LICENSE | No, installed separately | **Bundled-component notices require review when redistributing applicable artifacts.** The Linux wheel also depends on NVIDIA CUDA packages; **CUDA-related redistribution terms were not fully reviewed** |
| transformers | 5.18.0 | Apache-2.0 | https://pypi.org/pypi/transformers/5.18.0/json ; https://raw.githubusercontent.com/huggingface/transformers/main/LICENSE | No, installed separately | Keep license and notices when redistributing |
| tokenizers | 0.23.2 | Apache-2.0 | https://pypi.org/pypi/tokenizers/0.23.2/json ; https://raw.githubusercontent.com/huggingface/tokenizers/main/LICENSE | No, installed separately | Keep license and notices when redistributing |
| huggingface-hub | 1.33.0 | Apache-2.0 | https://pypi.org/pypi/huggingface-hub/1.33.0/json ; https://raw.githubusercontent.com/huggingface/huggingface_hub/main/LICENSE | No, installed separately | Keep license and notices when redistributing |
| opentelemetry-api, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc, opentelemetry-proto | 1.44.0 (as pinned) | Apache-2.0 (api, sdk and the OTLP gRPC exporter verified in package metadata; opentelemetry-proto is pinned in `stream-processor/requirements.txt` and was not separately checked in this review) | https://pypi.org/pypi/opentelemetry-api/1.44.0/json ; https://pypi.org/pypi/opentelemetry-sdk/1.44.0/json ; https://pypi.org/pypi/opentelemetry-exporter-otlp-proto-grpc/1.44.0/json | No, installed separately | Keep license and notices when redistributing |
| confluent-kafka | 2.15.0 | Apache-2.0 (PyPI classifier "Apache Software License"; LICENSE file listed) | https://pypi.org/pypi/confluent-kafka/2.15.0/json | No, installed separately | The binary wheels may bundle librdkafka and other native libraries; those were not audited |
| sentence-transformers/all-MiniLM-L6-v2 (model) | pinned revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` | `apache-2.0`, as declared in the model-card metadata at that revision. The model repository lists no separate LICENSE file | https://huggingface.co/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/1110a243fdf4706b3f48f1d95db1a4f5529b4d41 | No. Weights are downloaded separately by the user | **Model training-data terms were not independently audited** (the card lists a base model, `nreimers/MiniLM-L6-H384-uncased`, declared `mit`, and about twenty training datasets). If weights are redistributed, the Apache-2.0 license text and attribution apply |

## Limitations of this review

* **LGPL obligations** (psycopg, psycopg-binary, psycopg2-binary) must be reviewed if the affected libraries, or any image
  or bundle containing them, are redistributed.
* The **sentence-transformers NOTICE** must be preserved when applicable.
* **Torch's bundled-component notices** require review when redistributing applicable artifacts.
* **Native libraries inside psycopg-binary were not fully audited.**
* **CUDA-related redistribution terms were not fully reviewed.**
* **The full transitive dependency tree was not audited**, including the trees of dbt, scikit-learn, scipy and numpy.
* **Model training-data terms were not independently audited.**
* Container base images (for example Python, PostgreSQL and Kafka images referenced by the Docker configuration) were
  not reviewed here; they are pulled by the user and carry their own licenses.
* License identification relies on package metadata and upstream license files, not on a scan of installed artifacts.
* Third-party license texts are not reproduced in this file. Consult the official sources above.
