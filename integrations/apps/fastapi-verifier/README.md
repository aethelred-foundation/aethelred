# FastAPI Verifier Sample App

Reference application for:

- `aethelred.integrations.AethelredVerificationMiddleware`
- PyTorch-style wrapper (`wrap_pytorch_model`)
- HuggingFace pipeline wrapper (`wrap_transformers_pipeline`)
- LangChain wrapper (`wrap_langchain_runnable`)

## Endpoints

- `GET /health`
- `POST /infer/fraud`
- `POST /infer/text-risk`
- `POST /chain/normalize`
- `GET /verify/recent`

## Local Run

```bash
cd $AETHELRED_REPO_ROOT/apps/fastapi-verifier
pip install -r requirements.txt
pip install -e $AETHELRED_REPO_ROOT/sdk/python[integrations]
uvicorn app.main:app --reload --port 8000
```
