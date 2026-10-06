import fitz

doc = fitz.open('test_output.pdf')
page = doc[0]

# Check for images
images = page.get_images(full=True)
print(f"Images on page 1: {len(images)}")
for img in images:
    print(f"  {img}")

# Check white header bar exists
drawings = page.get_drawings()
white_rects = [d for d in drawings if d.get('fill') == (1.0, 1.0, 1.0) and d['rect'].y0 < 100]
print(f"\nWhite header rects: {len(white_rects)}")
for d in white_rects:
    print(f"  x={d['rect'].x0:.1f} to {d['rect'].x1:.1f}, y={d['rect'].y0:.1f} to {d['rect'].y1:.1f}")

# Check blue header row
blue_rects = [d for d in drawings if d.get('fill') and len(d['fill']) == 3 and abs(d['fill'][0] - 0.145) < 0.01]
print(f"\nBlue header rects: {len(blue_rects)}")
for d in blue_rects:
    print(f"  x={d['rect'].x0:.1f} to {d['rect'].x1:.1f}, y={d['rect'].y0:.1f} to {d['rect'].y1:.1f}")

doc.close()
