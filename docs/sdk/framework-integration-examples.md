# Framework Integration Examples

This guide provides complete, runnable integration examples for the most popular frameworks in the Python and TypeScript ecosystems. Each integration wraps existing inference or request-handling code to emit Aethelred verification envelopes automatically, with zero changes to your business logic.

---

## Table of Contents

- [PyTorch](#pytorch-integration)
- [FastAPI](#fastapi-integration)
- [Next.js Pages Router](#nextjs-pages-router)
- [Next.js App Router](#nextjs-app-router)
- [LangChain](#langchain-integration)
- [HuggingFace Transformers](#huggingface-transformers)
- [Keras / TensorFlow](#keras--tensorflow)

---

## PyTorch Integration

### Installation

```bash
pip install aethelred[pytorch]
# or
pip install aethelred torch
```

### Minimal Working Example

```python
import torch
from aethelred.integrations import wrap_pytorch_model, VerificationRecorder

recorder = VerificationRecorder()
model = torch.nn.Linear(10, 1)
verified_model = wrap_pytorch_model(model, recorder=recorder)

# Every inference now emits a verification envelope
input_tensor = torch.randn(1, 10)
output = verified_model(input_tensor)

print(f"Verification: {recorder.last_envelope}")
```

### What the Verification Envelope Contains

Each call to the wrapped model produces a `VerificationEnvelope` with the following fields:

| Field | Description |
|---|---|
| `trace_id` | Unique identifier for this inference call |
| `input_hash` | SHA-256 hash of the serialized input tensor |
| `output_hash` | SHA-256 hash of the serialized output tensor |
| `model_hash` | SHA-256 hash of the model's `state_dict` at the time of wrapping |
| `timestamp` | ISO 8601 timestamp of when inference occurred |
| `framework` | Always `"pytorch"` for this integration |
| `framework_version` | The installed PyTorch version string |

### Where Verification Data Appears

The `VerificationRecorder` stores envelopes in memory. You can access them through:

- `recorder.last_envelope` -- The most recent envelope.
- `recorder.envelopes` -- A list of all envelopes since recorder creation.
- `recorder.export_json(path)` -- Write all envelopes to a JSON file.
- `recorder.flush()` -- Clear stored envelopes and return them.

### Advanced Configuration

```python
verified_model = wrap_pytorch_model(
    model,
    recorder=recorder,
    hash_algorithm="sha512",        # Default: sha256
    include_gradients=False,        # Default: False
    capture_input_snapshot=True,    # Store a copy of input data (default: False)
    service_name="fraud-detector",  # Tag for multi-model setups
)
```

---

## FastAPI Integration

### Installation

```bash
pip install aethelred[fastapi]
# or
pip install aethelred fastapi uvicorn
```

### Minimal Working Example

```python
from fastapi import FastAPI
from aethelred.integrations import AethelredVerificationMiddleware

app = FastAPI()
app.add_middleware(
    AethelredVerificationMiddleware,
    include_paths=["/api/v1/*"],
    header_prefix="x-aethelred",
)

@app.post("/api/v1/predict")
async def predict(data: dict):
    return {"score": 0.85}

# Response headers will include x-aethelred-trace-id, x-aethelred-input-hash, etc.
```

### What the Verification Envelope Contains

The middleware computes hashes of the request body and response body, then injects verification data into response headers.

| Header | Description |
|---|---|
| `x-aethelred-trace-id` | Unique identifier for this request/response pair |
| `x-aethelred-input-hash` | SHA-256 hash of the raw request body |
| `x-aethelred-output-hash` | SHA-256 hash of the raw response body |
| `x-aethelred-timestamp` | ISO 8601 timestamp of when the response was generated |
| `x-aethelred-signature` | Ed25519 signature over the concatenated hash values |

### Where Verification Data Appears

- **Response headers** -- Every response matching `include_paths` carries the verification headers listed above.
- **Structured logs** -- If a Python logger named `aethelred.verification` is configured, the middleware emits a JSON log entry per request.
- **Recorder** -- Optionally, pass a `VerificationRecorder` to collect envelopes in memory.

### Advanced Configuration

```python
from aethelred.integrations import AethelredVerificationMiddleware

app.add_middleware(
    AethelredVerificationMiddleware,
    include_paths=["/api/v1/*"],
    exclude_paths=["/api/v1/health"],
    header_prefix="x-aethelred",
    hash_algorithm="sha256",
    sign_responses=True,              # Attach Ed25519 signature header
    signing_key_path="./keys/signing.pem",
    log_envelopes=True,               # Emit structured logs
    recorder=recorder,                # Optional in-memory recorder
)
```

---

## Next.js Pages Router

### Installation

```bash
npm install @aethelred/sdk
# or
yarn add @aethelred/sdk
```

### Minimal Working Example

```typescript
// pages/api/predict.ts
import { withAethelredApiRoute } from '@aethelred/sdk/integrations';

export default withAethelredApiRoute(
  async (req, res) => {
    const result = await processData(req.body);
    res.json(result);
  },
  { service: 'credit-scoring', component: 'predict-api' }
);
```

### What the Verification Envelope Contains

The wrapper intercepts the API route handler and attaches verification data to the response:

| Field | Description |
|---|---|
| `traceId` | Unique identifier for this request/response pair |
| `inputHash` | SHA-256 hash of `req.body` |
| `outputHash` | SHA-256 hash of the JSON response body |
| `service` | The `service` value from the options object |
| `component` | The `component` value from the options object |
| `timestamp` | ISO 8601 timestamp |

### Where Verification Data Appears

- **Response headers** -- `x-aethelred-trace-id`, `x-aethelred-input-hash`, `x-aethelred-output-hash`, and `x-aethelred-timestamp` are added to every response.
- **Server-side logs** -- A structured log entry is emitted via `console.log` (or a custom logger if configured) for each verified request.
- **`res.locals.aethelredEnvelope`** -- The full envelope object is available on the response for downstream middleware.

### Advanced Configuration

```typescript
import { withAethelredApiRoute } from '@aethelred/sdk/integrations';

export default withAethelredApiRoute(
  handler,
  {
    service: 'credit-scoring',
    component: 'predict-api',
    hashAlgorithm: 'sha256',
    signResponses: true,
    signingKeyPath: './keys/signing.pem',
    excludeMethods: ['GET', 'OPTIONS'],
    headerPrefix: 'x-aethelred',
  }
);
```

---

## Next.js App Router

### Installation

```bash
npm install @aethelred/sdk
# or
yarn add @aethelred/sdk
```

### Minimal Working Example

```typescript
// app/api/predict/route.ts
import { withAethelredRouteHandler } from '@aethelred/sdk/integrations';

export const POST = withAethelredRouteHandler(
  async (request) => {
    const body = await request.json();
    return Response.json({ score: 0.85 });
  },
  { service: 'credit-scoring' }
);
```

### What the Verification Envelope Contains

The App Router wrapper uses the Web Fetch API `Request`/`Response` types and produces the same envelope fields as the Pages Router integration:

| Field | Description |
|---|---|
| `traceId` | Unique identifier for this request/response pair |
| `inputHash` | SHA-256 hash of the request body |
| `outputHash` | SHA-256 hash of the response body |
| `service` | The `service` value from the options object |
| `timestamp` | ISO 8601 timestamp |

### Where Verification Data Appears

- **Response headers** -- Injected into the `Response` object returned by the handler. The header names follow the same pattern: `x-aethelred-trace-id`, `x-aethelred-input-hash`, etc.
- **Server-side logs** -- Structured log output for each verified request.

### Wrapping Multiple HTTP Methods

```typescript
// app/api/data/route.ts
import { withAethelredRouteHandler } from '@aethelred/sdk/integrations';

export const GET = withAethelredRouteHandler(
  async (request) => {
    const data = await fetchData();
    return Response.json(data);
  },
  { service: 'data-service', component: 'read' }
);

export const POST = withAethelredRouteHandler(
  async (request) => {
    const body = await request.json();
    const result = await processData(body);
    return Response.json(result);
  },
  { service: 'data-service', component: 'write' }
);
```

---

## LangChain Integration

### Installation

```bash
pip install aethelred[langchain]
# or
pip install aethelred langchain-core
```

### Minimal Working Example

```python
from langchain_core.runnables import RunnableLambda
from aethelred.integrations import wrap_langchain_runnable, VerificationRecorder

recorder = VerificationRecorder()
chain = RunnableLambda(lambda x: f"processed: {x}")
verified_chain = wrap_langchain_runnable(chain, recorder=recorder)

result = verified_chain.invoke("hello world")
print(f"Result: {result}")
print(f"Verification: {recorder.last_envelope}")
```

### What the Verification Envelope Contains

| Field | Description |
|---|---|
| `trace_id` | Unique identifier for this chain invocation |
| `input_hash` | SHA-256 hash of the serialized input |
| `output_hash` | SHA-256 hash of the serialized output |
| `chain_type` | The class name of the wrapped runnable (e.g., `RunnableLambda`) |
| `timestamp` | ISO 8601 timestamp |
| `framework` | Always `"langchain"` |

### Where Verification Data Appears

- `recorder.last_envelope` -- The most recent envelope.
- `recorder.envelopes` -- Full list of envelopes since creation.
- LangChain callbacks -- If you pass an `AethelredCallbackHandler`, envelopes are also emitted through the LangChain callback system.

### Wrapping Complex Chains

The wrapper works with any LangChain `Runnable`, including composed chains:

```python
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from aethelred.integrations import wrap_langchain_runnable, VerificationRecorder

recorder = VerificationRecorder()

# Build a multi-step chain
chain = (
    RunnablePassthrough()
    | RunnableLambda(lambda x: x.upper())
    | RunnableLambda(lambda x: f"Result: {x}")
)

verified_chain = wrap_langchain_runnable(chain, recorder=recorder)

result = verified_chain.invoke("test input")
print(f"Output: {result}")
# Output: "Result: TEST INPUT"

envelope = recorder.last_envelope
print(f"Input hash: {envelope.input_hash}")
print(f"Output hash: {envelope.output_hash}")
```

### Using the LangChain Callback Handler

```python
from aethelred.integrations import AethelredCallbackHandler

callback = AethelredCallbackHandler(
    service_name="qa-pipeline",
    log_to_file="verification_log.jsonl",
)

# Pass as a callback to any LangChain invocation
result = chain.invoke("input", config={"callbacks": [callback]})
```

---

## HuggingFace Transformers

### Installation

```bash
pip install aethelred[transformers]
# or
pip install aethelred transformers
```

### Minimal Working Example

```python
from transformers import pipeline
from aethelred.integrations import wrap_transformers_pipeline, VerificationRecorder

recorder = VerificationRecorder()
classifier = pipeline("sentiment-analysis")
verified_classifier = wrap_transformers_pipeline(classifier, recorder=recorder)

result = verified_classifier("Aethelred is amazing!")
print(f"Result: {result}")
```

### What the Verification Envelope Contains

| Field | Description |
|---|---|
| `trace_id` | Unique identifier for this pipeline call |
| `input_hash` | SHA-256 hash of the input text (or batch of texts) |
| `output_hash` | SHA-256 hash of the serialized pipeline output |
| `model_name` | The HuggingFace model identifier (e.g., `distilbert-base-uncased-finetuned-sst-2-english`) |
| `pipeline_task` | The pipeline task type (e.g., `sentiment-analysis`) |
| `timestamp` | ISO 8601 timestamp |
| `framework` | Always `"transformers"` |

### Where Verification Data Appears

- `recorder.last_envelope` -- The most recent envelope.
- `recorder.envelopes` -- Full history since recorder creation.
- Structured logs via the `aethelred.verification` logger.

### Wrapping Different Pipeline Types

```python
from transformers import pipeline
from aethelred.integrations import wrap_transformers_pipeline, VerificationRecorder

recorder = VerificationRecorder()

# Text generation
generator = pipeline("text-generation", model="gpt2")
verified_generator = wrap_transformers_pipeline(generator, recorder=recorder)
output = verified_generator("Once upon a time", max_length=50)

# Named entity recognition
ner = pipeline("ner", grouped_entities=True)
verified_ner = wrap_transformers_pipeline(ner, recorder=recorder)
entities = verified_ner("Aethelred is based in San Francisco")

# Question answering
qa = pipeline("question-answering")
verified_qa = wrap_transformers_pipeline(qa, recorder=recorder)
answer = verified_qa(question="What is Aethelred?", context="Aethelred is a verification network.")

# Each call produces a separate envelope
print(f"Total envelopes: {len(recorder.envelopes)}")
```

---

## Keras / TensorFlow

### Installation

```bash
pip install aethelred[tensorflow]
# or
pip install aethelred tensorflow
```

### Minimal Working Example

```python
import numpy as np
import tensorflow as tf
from aethelred.integrations import AethelredKerasCallback

# Build a simple model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation='relu', input_shape=(10,)),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dense(1),
])
model.compile(optimizer='adam', loss='mse')

# Generate sample data
x_train = np.random.randn(100, 10)
y_train = np.random.randn(100, 1)

# Train with Aethelred verification callback
callback = AethelredKerasCallback(capture_batch_events=False)
model.fit(x_train, y_train, epochs=5, callbacks=[callback])
```

### What the Verification Envelope Contains

The Keras callback produces envelopes at configurable granularity:

| Event | Envelope Fields |
|---|---|
| `on_train_begin` | `model_hash`, `model_architecture_hash`, `optimizer_config`, `timestamp` |
| `on_epoch_end` | `epoch`, `loss`, `metrics`, `weights_hash`, `timestamp` |
| `on_train_end` | `final_weights_hash`, `total_epochs`, `final_loss`, `timestamp` |
| `on_predict_batch_end` (if enabled) | `batch_input_hash`, `batch_output_hash`, `timestamp` |

### Where Verification Data Appears

- **Callback attributes** -- `callback.envelopes` stores all emitted envelopes.
- **Structured logs** -- Each event writes a JSON log line to the `aethelred.verification` logger.
- **Export** -- `callback.export_json(path)` writes all envelopes to disk.

### Advanced Configuration

```python
callback = AethelredKerasCallback(
    capture_batch_events=True,       # Log per-batch envelopes (default: False)
    capture_predictions=True,        # Hash prediction outputs (default: False)
    hash_algorithm="sha256",         # Hash algorithm (default: sha256)
    service_name="price-predictor",  # Tag for identification
    log_to_file="keras_verification.jsonl",  # Auto-export path
)

# Use with model.predict() for inference verification
predictions = model.predict(x_test, callbacks=[callback])

# Access the verification data
for envelope in callback.envelopes:
    print(f"Event: {envelope.event_type}, Hash: {envelope.weights_hash}")
```

### Wrapping a Keras Model for Inference Verification

If you only need inference-time verification (without training callbacks), use the model wrapper:

```python
from aethelred.integrations import wrap_keras_model, VerificationRecorder

recorder = VerificationRecorder()
verified_model = wrap_keras_model(model, recorder=recorder)

# Every predict call now emits a verification envelope
output = verified_model.predict(x_test)

print(f"Envelope: {recorder.last_envelope}")
print(f"Input hash: {recorder.last_envelope.input_hash}")
print(f"Output hash: {recorder.last_envelope.output_hash}")
```

---

## Common Patterns

### Combining Multiple Integrations

In production, you may use several integrations together. The `VerificationRecorder` can be shared across all of them:

```python
from aethelred.integrations import (
    VerificationRecorder,
    wrap_pytorch_model,
    AethelredVerificationMiddleware,
)

# Single recorder for all integrations
recorder = VerificationRecorder(
    service_name="credit-scoring-service",
    export_interval=100,  # Auto-export every 100 envelopes
    export_path="./verification_logs/",
)

# Use with PyTorch model
verified_model = wrap_pytorch_model(model, recorder=recorder)

# Use with FastAPI middleware
app.add_middleware(
    AethelredVerificationMiddleware,
    recorder=recorder,
    include_paths=["/api/v1/*"],
)
```

### Exporting Envelopes for Compliance

All integrations produce envelopes compatible with the Aethelred evidence bundle format. Export them for compliance audits:

```python
# Export all envelopes as a JSON file
recorder.export_json("verification_envelopes.json")

# Export as newline-delimited JSON (for log ingestion)
recorder.export_jsonl("verification_envelopes.jsonl")

# Convert envelopes to evidence bundles for regulatory submission
from aethelred.compliance import EvidenceBundleBuilder

builder = EvidenceBundleBuilder()
for envelope in recorder.envelopes:
    builder.add_envelope(envelope)

bundle = builder.build()
bundle.export("evidence_bundle.json")
```

---

## Further Resources

- [Enterprise Compliance Guide](../guides/enterprise-compliance.md) -- Regulatory compliance with Digital Seals
- [SDK API Reference](../api/rust/index.md) -- Full API documentation
- [Network Guide](../site/docs/guide/network.md) -- Validator network architecture
