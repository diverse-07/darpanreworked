"""Darpan's CPU-only graph and text models, initialized from source."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
from pathlib import Path

import torch
from torch import nn

CHECKPOINT = Path(__file__).with_name("darpan-models.json")
FORMAT_VERSION = 1
GRAPH_EPOCHS = 30
INTENT_EPOCHS = 65
TRAINING = {
    "tower": (
        "tower calls", "cell tower near fraud time", "Mansarovar tower ke paas fraud ke time pe kiske calls huye",
        "किस टावर पर कॉल हुई", "मानसरोवर टावर के पास किसके कॉल हुए", "show calls around sector",
        "tower par kaun tha", "टावर कॉल दिखाओ", "sector location co location coordinates", "सेक्टर के कॉल",
    ),
    "bank": (
        "money trail", "show bank transactions payments", "Rohan Mehta ka money trail dikhao",
        "खाते का लेनदेन दिखाओ", "रोहन मेहता का पैसे का लेनदेन", "paise ka transfer dikhao", "UPI mule account flow",
        "बैंक ट्रांसफर दिखाएं", "fund transactions ledger", "पैसों का trail",
    ),
    "contacts": ("show top contacts", "most frequent contacts", "rank contact counts", "who calls most",
                 "kis number par sabse zyada calls", "सबसे ज्यादा कॉल किस नंबर पर हुईं", "incoming outgoing ratio"),
    "common": ("common contacts between two suspects", "which numbers do both contact", "shared phone contacts",
               "dono ke common numbers", "दोनों के साझा नंबर", "समान नंबर खोजें"),
    "movement": ("serving tower timeline", "show tower usage sequence", "which towers were repeated",
                 "tower ka order", "टावर क्रम दिखाएं", "लोकेशन क्रम बताएं"),
    "device": ("detect IMEI and SIM changes", "handset swaps", "when did the IMSI change", "sim change kab hua",
               "सिम में बदलाव", "हैंडसेट कब बदला"),
    "night": ("show night activity", "late night calls", "raat ke calls dikhao", "रात की कॉल दिखाएं"),
    "calls": ("show calls in a time window", "filter calls between two times", "show calls at 02:00 to 04:00",
              "समय के अनुसार कॉल", "samay ke beech calls"),
    "summary": ("summarize the case", "case overview", "report summary", "case ka saar", "केस का सारांश"),
    "ipdr": ("show IPDR service indicators", "show app usage in logs", "what services are recorded",
             "ऐप उपयोग दिखाएं", "आईपीडीआर सेवाएं"),
    "other": (
        "hello how are you", "what is the weather", "write a report", "who is guilty", "कौन दोषी है",
        "upload a photo", "मौसम क्या है", "suno ek kahani", "delete this case", "show me the records",
    ),
}
INTENTS = tuple(TRAINING)


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def parameter(shape, bound, rng):
    data = torch.empty(shape, dtype=torch.float32, device="cpu")
    return nn.Parameter(data.uniform_(-bound, bound, generator=rng))


class ForensicGAT(nn.Module):
    """Single-head masked attention with separate risk and link decoders."""

    def __init__(self):
        super().__init__()
        rng = torch.Generator(device="cpu").manual_seed(63)
        self.projection = parameter((16, 6), 1 / math.sqrt(6), rng)
        self.attention = parameter((2, 16), math.sqrt(6 / 18), rng)
        self.class_weight = parameter((5, 22), 1 / math.sqrt(22), rng)
        self.class_bias = parameter((5,), 1 / math.sqrt(22), rng)
        self.link_weight = parameter((12, 16), 1 / math.sqrt(16), rng)
        self.link_bias = parameter((12,), 1 / math.sqrt(16), rng)

    def forward(self, x, adjacency):
        h = x @ self.projection.T
        from_node = h @ self.attention[0]
        to_node = h @ self.attention[1]
        coefficients = from_node[:, None] + to_node[None, :]
        coefficients = torch.where(coefficients >= 0, coefficients, 0.2 * coefficients)
        coefficients = coefficients.masked_fill(~adjacency, -torch.inf)
        probabilities = (coefficients - coefficients.logsumexp(dim=1, keepdim=True)).exp()
        pooled = probabilities @ h
        embedding = torch.where(pooled >= 0, pooled, pooled.clamp(max=0).expm1())
        logits = torch.cat((x, embedding), dim=1) @ self.class_weight.T + self.class_bias
        z = embedding @ self.link_weight.T + self.link_bias
        return logits, z @ z.T / math.sqrt(z.shape[-1])


class IntentNet(nn.Module):
    """Train a bilingual word/bigram classifier with one tanh hidden layer."""

    def __init__(self, vocab_size):
        super().__init__()
        rng = torch.Generator(device="cpu").manual_seed(71)
        self.input_weight = parameter((20, vocab_size), 1 / math.sqrt(vocab_size), rng)
        self.input_bias = parameter((20,), 1 / math.sqrt(vocab_size), rng)
        self.output_weight = parameter((len(INTENTS), 20), 1 / math.sqrt(20), rng)
        self.output_bias = parameter((len(INTENTS),), 1 / math.sqrt(20), rng)

    def forward(self, features):
        hidden = (features @ self.input_weight.T + self.input_bias).tanh()
        return hidden @ self.output_weight.T + self.output_bias


def cross_entropy(logits, labels):
    chosen = logits.gather(1, labels[:, None]).squeeze(1)
    return (logits.logsumexp(dim=1) - chosen).mean()


def train(model, loss_for, epochs, rate):
    """Compute gradients with autograd and apply Adam updates directly."""
    weights = tuple(model.parameters())
    moments = [(torch.zeros_like(weight), torch.zeros_like(weight)) for weight in weights]
    for step in range(1, epochs + 1):
        gradients = torch.autograd.grad(loss_for(model), weights)
        with torch.no_grad():
            for weight, gradient, (mean, variance) in zip(weights, gradients, moments):
                mean.lerp_(gradient, 0.1)
                variance.mul_(0.999).addcmul_(gradient, gradient, value=0.001)
                step_mean = mean / (1 - 0.9 ** step)
                step_scale = (variance / (1 - 0.999 ** step)).sqrt().add_(1e-8)
                weight.addcdiv_(step_mean, step_scale, value=-rate)
    return model.eval()


def graph_fingerprint(features, adjacency, labels):
    return digest({"features": features.tolist(), "adjacency": adjacency.tolist(), "labels": labels.tolist()})


def train_graph(features, adjacency, labels):
    mask = adjacency | torch.eye(len(features), dtype=torch.bool)
    rows, columns = torch.triu_indices(len(features), len(features), offset=1)
    edge_labels = adjacency[rows, columns].float()

    def loss_for(model):
        logits, links = model(features, mask)
        pair_logits = links[rows, columns]
        edge_loss = torch.logaddexp(torch.zeros_like(pair_logits), pair_logits) - edge_labels * pair_logits
        return cross_entropy(logits, labels) + 0.25 * edge_loss.mean()

    return train(ForensicGAT(), loss_for, GRAPH_EPOCHS, 0.045)


def query_tokens(text):
    words = re.findall(r"[\w\u0900-\u097f]+", unicodedata.normalize("NFKC", text).casefold())
    return [*words, *(a + " " + b for a, b in zip(words, words[1:]))]


def vector(text, vocabulary):
    tokens = set(query_tokens(text))
    return [float(word in tokens) for word in vocabulary]


def intent_training_data():
    vocabulary = sorted({word for examples in TRAINING.values() for example in examples for word in query_tokens(example)})
    examples = torch.tensor([vector(example, vocabulary) for rows in TRAINING.values() for example in rows])
    labels = torch.tensor([i for i, rows in enumerate(TRAINING.values()) for _ in rows])
    return vocabulary, examples, labels


def train_intent(vocabulary, examples, labels):
    return train(IntentNet(len(vocabulary)), lambda model: cross_entropy(model(examples), labels),
                 INTENT_EPOCHS, 0.04)


def weight_values(model):
    return {name: weight.detach().tolist() for name, weight in model.state_dict().items()}


def restore_weights(model, payload):
    targets = model.state_dict()
    if not isinstance(payload, dict) or payload.keys() != targets.keys():
        raise ValueError("Checkpoint parameter keys differ from the model")
    tensors = {}
    for name, prototype in targets.items():
        tensor = torch.tensor(payload[name], dtype=prototype.dtype, device="cpu")
        if tensor.shape != prototype.shape or not bool(tensor.isfinite().all()):
            raise ValueError(f"Invalid checkpoint tensor {name}")
        tensors[name] = tensor
    model.load_state_dict(tensors, strict=True)
    return model.eval()


def read_checkpoint(path=CHECKPOINT):
    try:
        with path.open("rb") as file:
            raw = file.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return {}
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("version") != FORMAT_VERSION:
            return {}
        models = payload["models"]
        return models if isinstance(models, dict) and digest(models) == payload.get("sha256") else {}
    except (OSError, ValueError, KeyError, RecursionError):
        return {}


def graph_from_checkpoint(features, adjacency, labels):
    record = read_checkpoint().get("graph")
    if not isinstance(record, dict) or record.get("input_sha256") != graph_fingerprint(features, adjacency, labels):
        return None
    try:
        return restore_weights(ForensicGAT(), record["weights"])
    except (ValueError, KeyError, TypeError, RuntimeError, OverflowError):
        return None


def load_intent():
    vocabulary, examples, labels = intent_training_data()
    record = read_checkpoint().get("intent")
    if (isinstance(record, dict) and record.get("input_sha256") == digest(TRAINING)
            and record.get("vocabulary") == vocabulary):
        try:
            return vocabulary, restore_weights(IntentNet(len(vocabulary)), record["weights"])
        except (ValueError, KeyError, TypeError, RuntimeError, OverflowError):
            pass
    return vocabulary, train_intent(vocabulary, examples, labels)


def write_checkpoint(path, graph, features, adjacency, labels):
    vocabulary, examples, targets = intent_training_data()
    intent = train_intent(vocabulary, examples, targets)
    models = {
        "graph": {"input_sha256": graph_fingerprint(features, adjacency, labels), "epochs": GRAPH_EPOCHS,
                  "weights": weight_values(graph)},
        "intent": {"input_sha256": digest(TRAINING), "epochs": INTENT_EPOCHS, "vocabulary": vocabulary,
                   "weights": weight_values(intent)},
    }
    bundle = {"version": FORMAT_VERSION, "sha256": digest(models), "models": models}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(canonical_json(bundle) + b"\n")
            stream.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return bundle["sha256"]
