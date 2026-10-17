"""Sample inference pipeline loading Hugging Face models via AutoModel."""

from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore[import-not-found]


def load_chat_pipeline() -> tuple[object, object]:
    tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3-8B")
    model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3-8B")
    return tokenizer, model
