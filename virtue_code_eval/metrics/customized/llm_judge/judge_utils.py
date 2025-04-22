# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import base64
import io

from PIL import Image


def image_to_b64(image_path: str, image_format: str = "PNG") -> str:
    image = Image.open(image_path)
    buffer = io.BytesIO()
    image.save(buffer, format=image_format)
    img_base64 = base64.b64encode(buffer.getvalue())
    return img_base64.decode("utf-8")
