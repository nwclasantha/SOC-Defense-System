"""
Image Optimization Module
Optimizes images for security reports, dashboards, and exports
Reduces file size while maintaining quality for documentation
"""

from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageEnhance
from io import BytesIO
import os
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import base64

class ImageOptimizer:
    """
    Optimizes images for security reports and dashboards
    Provides compression, resizing, watermarking, and format conversion
    """

    def __init__(self):
        self.optimization_stats = {
            "images_processed": 0,
            "total_bytes_saved": 0,
            "average_compression_ratio": 0.0
        }

    def optimize_image(self,
                      image_path: str,
                      output_path: str = None,
                      quality: int = 85,
                      max_size: Tuple[int, int] = None,
                      format: str = None) -> Dict[str, Any]:
        """
        Optimize image file

        Args:
            image_path: Path to input image
            output_path: Path for output (None = overwrite)
            quality: JPEG quality (1-100)
            max_size: Maximum dimensions (width, height)
            format: Output format (JPEG, PNG, WEBP)

        Returns:
            Optimization results
        """
        if not os.path.exists(image_path):
            return {"error": "Image not found"}

        # Open image
        img = Image.open(image_path)
        original_size = os.path.getsize(image_path)
        original_format = img.format

        # Convert RGBA to RGB if saving as JPEG
        if format == "JPEG" and img.mode == "RGBA":
            # Create white background
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])  # Use alpha as mask
            img = background

        # Resize if needed
        if max_size:
            img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Determine output format
        output_format = format or original_format or "JPEG"
        output_path = output_path or image_path

        # Optimize based on format
        if output_format.upper() == "JPEG":
            img.save(output_path, "JPEG", quality=quality, optimize=True)
        elif output_format.upper() == "PNG":
            img.save(output_path, "PNG", optimize=True)
        elif output_format.upper() == "WEBP":
            img.save(output_path, "WEBP", quality=quality)
        else:
            img.save(output_path, output_format, optimize=True)

        # Calculate results
        new_size = os.path.getsize(output_path)
        bytes_saved = original_size - new_size
        compression_ratio = (1 - new_size / original_size) * 100 if original_size > 0 else 0

        # Update stats
        self.optimization_stats["images_processed"] += 1
        self.optimization_stats["total_bytes_saved"] += bytes_saved

        return {
            "original_size_bytes": original_size,
            "optimized_size_bytes": new_size,
            "bytes_saved": bytes_saved,
            "compression_ratio_percent": compression_ratio,
            "output_path": output_path,
            "output_format": output_format
        }

    def create_thumbnail(self,
                        image_path: str,
                        output_path: str,
                        size: Tuple[int, int] = (150, 150)) -> str:
        """
        Create thumbnail image

        Args:
            image_path: Input image
            output_path: Output path
            size: Thumbnail size

        Returns:
            Path to thumbnail
        """
        img = Image.open(image_path)
        img.thumbnail(size, Image.Resampling.LANCZOS)
        img.save(output_path, "JPEG", quality=85, optimize=True)

        return output_path

    def add_watermark(self,
                     image_path: str,
                     output_path: str,
                     watermark_text: str = "CONFIDENTIAL",
                     position: str = "bottom-right",
                     opacity: int = 128) -> str:
        """
        Add watermark to image

        Args:
            image_path: Input image
            output_path: Output path
            watermark_text: Text to watermark
            position: Position (top-left, top-right, bottom-left, bottom-right, center)
            opacity: Opacity (0-255)

        Returns:
            Path to watermarked image
        """
        img = Image.open(image_path).convert("RGBA")

        # Create watermark layer
        watermark = Image.new("RGBA", img.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)

        # Try to use a font, fallback to default
        try:
            font = ImageFont.truetype("arial.ttf", 36)
        except (IOError, OSError):
            font = ImageFont.load_default()

        # Get text bounding box
        bbox = draw.textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # Calculate position
        width, height = img.size

        if position == "top-left":
            x, y = 20, 20
        elif position == "top-right":
            x, y = width - text_width - 20, 20
        elif position == "bottom-left":
            x, y = 20, height - text_height - 20
        elif position == "bottom-right":
            x, y = width - text_width - 20, height - text_height - 20
        elif position == "center":
            x, y = (width - text_width) // 2, (height - text_height) // 2
        else:
            x, y = 20, height - text_height - 20

        # Draw text with opacity
        draw.text((x, y), watermark_text, font=font, fill=(255, 255, 255, opacity))

        # Composite
        watermarked = Image.alpha_composite(img, watermark)

        # Convert back to RGB for JPEG
        final = Image.new("RGB", watermarked.size, (255, 255, 255))
        final.paste(watermarked, mask=watermarked.split()[-1])

        final.save(output_path, "JPEG", quality=95)

        return output_path

    def batch_optimize(self,
                      input_dir: str,
                      output_dir: str = None,
                      quality: int = 85,
                      max_size: Tuple[int, int] = None) -> Dict[str, Any]:
        """
        Batch optimize all images in directory

        Args:
            input_dir: Input directory
            output_dir: Output directory (None = same as input)
            quality: JPEG quality
            max_size: Maximum dimensions

        Returns:
            Batch optimization results
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir) if output_dir else input_path

        if not input_path.exists():
            return {"error": "Input directory not found"}

        output_path.mkdir(parents=True, exist_ok=True)

        # Supported formats
        supported_formats = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}

        results = []
        total_saved = 0

        for image_file in input_path.iterdir():
            if image_file.suffix.lower() in supported_formats:
                output_file = output_path / image_file.name

                result = self.optimize_image(
                    str(image_file),
                    str(output_file),
                    quality=quality,
                    max_size=max_size
                )

                results.append({
                    "filename": image_file.name,
                    **result
                })

                if "bytes_saved" in result:
                    total_saved += result["bytes_saved"]

        return {
            "images_processed": len(results),
            "total_bytes_saved": total_saved,
            "results": results
        }

    def convert_to_base64(self, image_path: str) -> str:
        """
        Convert image to base64 string for embedding

        Args:
            image_path: Path to image

        Returns:
            Base64 encoded string
        """
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode("utf-8")

    def create_chart_from_data(self,
                               data: Dict[str, float],
                               output_path: str,
                               chart_type: str = "bar",
                               title: str = "",
                               size: Tuple[int, int] = (800, 600)) -> str:
        """
        Create simple chart image from data

        Args:
            data: Dictionary of labels to values
            output_path: Output path
            chart_type: bar, pie (simple charts)
            title: Chart title
            size: Image size

        Returns:
            Path to chart image
        """
        width, height = size

        # Create image
        img = Image.new("RGB", size, "white")
        draw = ImageDraw.Draw(img)

        # Try to load font
        try:
            title_font = ImageFont.truetype("arial.ttf", 24)
            label_font = ImageFont.truetype("arial.ttf", 16)
        except (IOError, OSError):
            title_font = ImageFont.load_default()
            label_font = ImageFont.load_default()

        # Draw title
        if title:
            draw.text((20, 20), title, fill="black", font=title_font)

        # Chart area
        chart_top = 80
        chart_left = 100
        chart_width = width - 150
        chart_height = height - 150

        if chart_type == "bar":
            self._draw_bar_chart(draw, data, chart_left, chart_top,
                                chart_width, chart_height, label_font)
        elif chart_type == "pie":
            self._draw_pie_chart(draw, data, chart_left, chart_top,
                                chart_width, chart_height, label_font)

        img.save(output_path, "PNG")
        return output_path

    def apply_security_blur(self,
                           image_path: str,
                           output_path: str,
                           regions: List[Tuple[int, int, int, int]] = None) -> str:
        """
        Apply blur to sensitive regions (for redaction)

        Args:
            image_path: Input image
            output_path: Output path
            regions: List of (x1, y1, x2, y2) regions to blur

        Returns:
            Path to blurred image
        """
        img = Image.open(image_path)

        if regions:
            for region in regions:
                x1, y1, x2, y2 = region

                # Extract region
                cropped = img.crop((x1, y1, x2, y2))

                # Apply strong blur
                blurred = cropped.filter(ImageFilter.GaussianBlur(radius=15))

                # Paste back
                img.paste(blurred, (x1, y1))
        else:
            # Blur entire image
            img = img.filter(ImageFilter.GaussianBlur(radius=10))

        img.save(output_path, quality=95)
        return output_path

    def compress_for_report(self, image_path: str, output_path: str = None) -> Dict[str, Any]:
        """
        Optimize image specifically for PDF reports

        Args:
            image_path: Input image
            output_path: Output path

        Returns:
            Optimization results
        """
        return self.optimize_image(
            image_path,
            output_path,
            quality=80,
            max_size=(1200, 1200),
            format="JPEG"
        )

    def _draw_bar_chart(self, draw, data: Dict, left: int, top: int,
                       width: int, height: int, font):
        """Draw simple bar chart"""
        if not data:
            return

        max_value = max(data.values())
        bar_width = width // (len(data) * 2)
        spacing = bar_width // 2

        colors = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6"]

        x = left
        for i, (label, value) in enumerate(data.items()):
            bar_height = int((value / max_value) * height) if max_value > 0 else 0

            # Draw bar
            color = colors[i % len(colors)]
            draw.rectangle(
                [x, top + height - bar_height, x + bar_width, top + height],
                fill=color
            )

            # Draw label
            draw.text((x, top + height + 10), label[:10], fill="black", font=font)

            # Draw value
            draw.text((x, top + height - bar_height - 25),
                     str(int(value)), fill="black", font=font)

            x += bar_width + spacing

    def _draw_pie_chart(self, draw, data: Dict, left: int, top: int,
                       width: int, height: int, font):
        """Draw simple pie chart"""
        if not data:
            return

        total = sum(data.values())
        if total == 0:
            return

        # Calculate center and radius
        center_x = left + width // 2
        center_y = top + height // 2
        radius = min(width, height) // 2 - 50

        colors = ["#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6"]

        start_angle = 0

        for i, (label, value) in enumerate(data.items()):
            # Calculate slice angle
            angle = (value / total) * 360

            # Draw pie slice
            color = colors[i % len(colors)]
            draw.pieslice(
                [center_x - radius, center_y - radius,
                 center_x + radius, center_y + radius],
                start=start_angle,
                end=start_angle + angle,
                fill=color
            )

            # Draw label
            label_angle = start_angle + angle / 2
            label_x = center_x + int(radius * 1.2 *
                     __import__('math').cos(__import__('math').radians(label_angle)))
            label_y = center_y + int(radius * 1.2 *
                     __import__('math').sin(__import__('math').radians(label_angle)))

            draw.text((label_x, label_y), f"{label}\n{int(value)}",
                     fill="black", font=font)

            start_angle += angle

    def enhance_screenshot(self,
                          image_path: str,
                          output_path: str,
                          sharpen: bool = True,
                          contrast: float = 1.2,
                          brightness: float = 1.1) -> str:
        """
        Enhance screenshot quality

        Args:
            image_path: Input screenshot
            output_path: Output path
            sharpen: Apply sharpening
            contrast: Contrast multiplier
            brightness: Brightness multiplier

        Returns:
            Path to enhanced image
        """
        img = Image.open(image_path)

        # Enhance contrast
        if contrast != 1.0:
            enhancer = ImageEnhance.Contrast(img)
            img = enhancer.enhance(contrast)

        # Enhance brightness
        if brightness != 1.0:
            enhancer = ImageEnhance.Brightness(img)
            img = enhancer.enhance(brightness)

        # Sharpen
        if sharpen:
            img = img.filter(ImageFilter.SHARPEN)

        img.save(output_path, quality=95, optimize=True)

        return output_path

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            **self.optimization_stats,
            "total_mb_saved": self.optimization_stats["total_bytes_saved"] / (1024 * 1024)
        }
