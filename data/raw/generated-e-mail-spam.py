import datasets
import pandas as pd

_CITATION = """\
@InProceedings{huggingface:dataset,
title = {generated-e-mail-spam},
author = {TrainingDataPro},
year = {2023}
}
"""

_DESCRIPTION = """
The dataset consists of a **CSV file** containing of 300 generated email spam messages.
Each row in the file represents a separate email message, its *title and text.*
The dataset aims to facilitate the analysis and detection of spam emails.
The dataset can be used for various purposes, such as *training machine learning
algorithms to classify and filter spam emails, studying spam email patterns,
or analyzing text-based features of spam messages*.
"""
_NAME = "generated-e-mail-spam"

_HOMEPAGE = f"https://huggingface.co/datasets/TrainingDataPro/{_NAME}"

_LICENSE = ""

_DATA = f"https://huggingface.co/datasets/TrainingDataPro/{_NAME}/resolve/main/data/"


class GeneratedEMailSpam(datasets.GeneratorBasedBuilder):
    def _info(self):
        return datasets.DatasetInfo(
            description=_DESCRIPTION,
            features=datasets.Features(
                {
                    "title": datasets.Value("string"),
                    "text": datasets.Value("large_string"),
                }
            ),
            supervised_keys=None,
            homepage=_HOMEPAGE,
            citation=_CITATION,
        )

    def _split_generators(self, dl_manager):
        annotations = dl_manager.download(f"{_DATA}{_NAME}.csv")
        return [
            datasets.SplitGenerator(
                name=datasets.Split.TRAIN,
                gen_kwargs={"annotations": annotations},
            ),
        ]

    def _generate_examples(self, annotations):
        annotations_df = pd.read_csv(
            annotations,
            sep="\t",
            encoding="unicode_escape",
        )

        for idx, title, text in annotations_df.itertuples():
            yield idx, {
                "title": title,
                "text": text,
            }
