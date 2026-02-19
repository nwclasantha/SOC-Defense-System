"""
Generate AI-SOC Central Logo
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_logo():
    """Create AI-SOC Central logo"""
    # Create high-res image (512x512)
    size = 512
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Colors
    bg_color = (13, 17, 23)  # Dark background
    accent_color = (0, 212, 255)  # Cyan accent
    shield_color = (30, 40, 55)  # Dark blue-gray

    # Draw circular background
    margin = 20
    draw.ellipse([margin, margin, size-margin, size-margin], fill=bg_color, outline=accent_color, width=4)

    # Draw shield shape
    shield_points = [
        (size//2, 80),  # Top center
        (size-100, 150),  # Top right
        (size-100, 320),  # Bottom right curve start
        (size//2, 430),  # Bottom point
        (100, 320),  # Bottom left curve start
        (100, 150),  # Top left
    ]
    draw.polygon(shield_points, fill=shield_color, outline=accent_color, width=3)

    # Draw inner shield highlight
    inner_margin = 30
    inner_points = [
        (size//2, 80 + inner_margin),
        (size-100-inner_margin, 150 + inner_margin//2),
        (size-100-inner_margin, 320 - inner_margin//2),
        (size//2, 430 - inner_margin),
        (100+inner_margin, 320 - inner_margin//2),
        (100+inner_margin, 150 + inner_margin//2),
    ]
    draw.polygon(inner_points, fill=None, outline=(0, 180, 220), width=2)

    # Draw AI brain/circuit pattern inside shield
    center_x, center_y = size//2, 230

    # Central node
    draw.ellipse([center_x-25, center_y-25, center_x+25, center_y+25], fill=accent_color)

    # Connection lines radiating out
    nodes = [
        (center_x-80, center_y-60),
        (center_x+80, center_y-60),
        (center_x-90, center_y+40),
        (center_x+90, center_y+40),
        (center_x, center_y-100),
        (center_x, center_y+100),
    ]

    for nx, ny in nodes:
        # Draw connection line
        draw.line([(center_x, center_y), (nx, ny)], fill=accent_color, width=3)
        # Draw node
        draw.ellipse([nx-12, ny-12, nx+12, ny+12], fill=(0, 150, 200))

    # Add text "AI" in the center
    try:
        font = ImageFont.truetype("arial.ttf", 36)
    except:
        font = ImageFont.load_default()

    text = "AI"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    draw.text((center_x - text_width//2, center_y - text_height//2 - 5), text, fill=(13, 17, 23), font=font)

    # Save logo
    logo_path = os.path.join(os.path.dirname(__file__), "ai_soc_central_logo.png")
    img.save(logo_path, "PNG")
    print(f"Logo saved to: {logo_path}")

    # Create icon version (64x64)
    icon = img.resize((64, 64), Image.LANCZOS)
    icon_path = os.path.join(os.path.dirname(__file__), "ai_soc_central_icon.png")
    icon.save(icon_path, "PNG")
    print(f"Icon saved to: {icon_path}")

    # Create favicon (32x32)
    favicon = img.resize((32, 32), Image.LANCZOS)
    favicon_path = os.path.join(os.path.dirname(__file__), "favicon.png")
    favicon.save(favicon_path, "PNG")
    print(f"Favicon saved to: {favicon_path}")

    # Create ICO file for Windows
    try:
        ico_path = os.path.join(os.path.dirname(__file__), "ai_soc_central.ico")
        img.save(ico_path, format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
        print(f"ICO saved to: {ico_path}")
    except Exception as e:
        print(f"Could not create ICO: {e}")

    return logo_path

if __name__ == "__main__":
    create_logo()
