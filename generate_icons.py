from PIL import Image, ImageDraw, ImageFont
import os

os.makedirs('static/icons', exist_ok=True)

def create_icon(size, color='#38bdf8', text='🛡'):
    img = Image.new('RGBA', (size, size), (11, 15, 26, 255))  # #0b0f1a
    draw = ImageDraw.Draw(img)
    # Try to load a font, fallback to default
    try:
        font = ImageFont.truetype("arial.ttf", size=int(size*0.6))
    except:
        font = ImageFont.load_default()
    # Center text
    bbox = draw.textbbox((0,0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (size - text_width) / 2
    y = (size - text_height) / 2 - 10
    draw.text((x, y), text, font=font, fill=color)
    img.save(f'static/icons/icon-{size}.png')

create_icon(192)
create_icon(512)
print("✅ Icons created in static/icons/")