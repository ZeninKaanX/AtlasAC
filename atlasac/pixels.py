"""Small Minecraft-style sprites rendered by native Qt with nearest-neighbour pixels."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap,QTransform,QRegion
from .paths import ASSETS

def clownfish(height):
    # Original tropical-fish item from the user's installed Minecraft client.
    image=QPixmap(str(ASSETS/'minecraft-clownfish.png'))
    image=image.transformed(QTransform().rotate(45),Qt.TransformationMode.FastTransformation)
    image=image.copy(QRegion(image.mask()).boundingRect()).transformed(QTransform().scale(-1,1),Qt.TransformationMode.FastTransformation)
    return image.scaledToHeight(height,Qt.TransformationMode.FastTransformation)

def shark(height):
    return QPixmap(str(ASSETS/'minecraft-shark.png')).scaledToHeight(height,Qt.TransformationMode.FastTransformation)
