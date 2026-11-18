"""Classifier agent: labels finding titles the rules could not place as OS or application issues."""
from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.schemas import TopicLabels
from guardrails.input_checks import strip_html, truncate

BATCH_SIZE = 40


class TopicClassifierAgent(BaseAgent):
    name = "classifier"
    system_prompt = "classifier.md"
    template = "classify_topics.md"
    schema = TopicLabels

    def classify(self, titles: list[str]) -> tuple[dict[str, str], dict[str, Any]]:
        """Return {title: topic}. Titles are sent in numbered batches and matched back by number."""
        labels: dict[str, str] = {}
        details: dict[str, Any] = {}
        for start in range(0, len(titles), BATCH_SIZE):
            batch = titles[start:start + BATCH_SIZE]
            numbered = "\n".join(f"{index}. {truncate(strip_html(title), 200)}" for index, title in enumerate(batch, 1))
            answer, details = self.run(titles=numbered)
            for label in answer.labels:
                if 1 <= label.id <= len(batch):
                    labels[batch[label.id - 1]] = label.topic
        return labels, details
