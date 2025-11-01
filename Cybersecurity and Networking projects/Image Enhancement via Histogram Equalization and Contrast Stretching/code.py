import cv2
import matplotlib.pyplot as plt
import numpy as np
import os


def manual_histogram(image):
    """
    Manually compute histogram without using library functions
    Returns: histogram array of size 256
    """
    hist = np.zeros(256, dtype=int)
    rows, cols = image.shape

    for i in range(rows):
        for j in range(cols):
            pixel_value = image[i, j]
            hist[pixel_value] += 1

    return hist


def manual_cumulative_histogram(hist):
    """
    Manually compute cumulative histogram
    Returns: cumulative histogram array
    """
    cumsum = np.zeros(256, dtype=int)
    cumsum[0] = hist[0]

    for i in range(1, 256):
        cumsum[i] = cumsum[i - 1] + hist[i]

    return cumsum


def manual_histogram_equalization(image):
    """
    Manually perform histogram equalization
    Steps:
    1. Calculate histogram
    2. Calculate PMF (Probability Mass Function)
    3. Calculate CDF (Cumulative Distribution Function)
    4. Multiply CDF by (L-1) where L=256
    5. Round to get new intensity values
    6. Map old intensities to new intensities
    """
    hist = manual_histogram(image)
    rows, cols = image.shape
    total_pixels = rows * cols

    pmf = hist / total_pixels

    cdf = np.zeros(256)
    cdf[0] = pmf[0]
    for i in range(1, 256):
        cdf[i] = cdf[i - 1] + pmf[i]

    equalized_values = np.round(cdf * 255).astype(np.uint8)

    equalized_image = np.zeros_like(image)
    for i in range(rows):
        for j in range(cols):
            equalized_image[i, j] = equalized_values[image[i, j]]

    return equalized_image


def manual_contrast_stretching(image):
    """
    Manually perform contrast stretching
    Formula: new_pixel = ((pixel - min) / (max - min)) * 255
    """
    min_val = np.min(image)
    max_val = np.max(image)

    print(f"Original intensity range: [{min_val}, {max_val}]")

    rows, cols = image.shape
    stretched_image = np.zeros_like(image, dtype=np.uint8)

    if max_val == min_val:
        return image

    for i in range(rows):
        for j in range(cols):
            stretched_image[i, j] = int(((image[i, j] - min_val) / (max_val - min_val)) * 255)

    return stretched_image


# ============================================================
# MAIN PROGRAM START
# ============================================================

print("\n" + "=" * 60)
print("Image processing lab task 1")
print("=" * 60)

# IMAGE LOADING
print("\n" + "=" * 60)
print("STEP 1: LOADING IMAGE")
print("=" * 60)

possible_names = [
    'mountain.jpg', 'mountain.png', 'mountain.jpeg',
    'image.jpg', 'image.png',
    'test.jpg', 'test.png',
    'sample.jpg', 'sample.png'
]

image = None
image_path = None

for filename in possible_names:
    try:
        temp_image = cv2.imread(filename, cv2.IMREAD_GRAYSCALE)
        if temp_image is not None:
            image = temp_image
            image_path = filename
            break
    except:
        continue

if image is None:
    print("\nPlease enter image path")

    user_path = input("\nImage path: ").strip().strip('"').strip("'")

    if user_path:
        image = cv2.imread(user_path, cv2.IMREAD_GRAYSCALE)
        if image is not None:
            image_path = user_path

if image is None:
    print("\n" + "=" * 60)
    print("ERROR: Could not load image!")
    print("=" * 60)
    print("\nPlease follow these steps:")
    print("1. Save your mountain image in the same folder as this script")
    print("2. Rename it to 'mountain.jpg'")
    print("3. Run the script again")
    print(f"\nCurrent working directory: {os.getcwd()}")
    exit()

print(f"\n✓ Image loaded successfully: {image_path}")
print(f"  Shape: {image.shape}, dtype: {image.dtype}")

# ============================================================
# PART 1: HISTOGRAM COMPUTATION
# ============================================================
print("\n" + "=" * 60)
print("STEP 2: COMPUTING HISTOGRAMS")
print("=" * 60)

hist_opencv = cv2.calcHist([image], [0], None, [256], [0, 256])
hist_opencv = hist_opencv.flatten()
print("✓ Histogram computed using OpenCV")

hist_manual = manual_histogram(image)
print("✓ Histogram computed using Manual Implementation")

# ============================================================
# PART 2: CUMULATIVE HISTOGRAM
# ============================================================
print("\n" + "=" * 60)
print("STEP 3: COMPUTING CUMULATIVE HISTOGRAMS")
print("=" * 60)

cumhist_opencv = np.cumsum(hist_opencv)
print("✓ Cumulative histogram computed using OpenCV/NumPy")

cumhist_manual = manual_cumulative_histogram(hist_manual)
print("✓ Cumulative histogram computed using Manual Implementation")

# ============================================================
# PART 3: HISTOGRAM EQUALIZATION
# ============================================================
print("\n" + "=" * 60)
print("STEP 4: PERFORMING HISTOGRAM EQUALIZATION")
print("=" * 60)

equalized_opencv = cv2.equalizeHist(image)
hist_eq_opencv = cv2.calcHist([equalized_opencv], [0], None, [256], [0, 256]).flatten()
print("✓ Histogram equalization performed using OpenCV")

equalized_manual = manual_histogram_equalization(image)
hist_eq_manual = manual_histogram(equalized_manual)
print("✓ Histogram equalization performed using Manual Implementation")

# ============================================================
# PART 4: CONTRAST STRETCHING
# ============================================================
print("\n" + "=" * 60)
print("STEP 5: PERFORMING CONTRAST STRETCHING")
print("=" * 60)

stretched_opencv = cv2.normalize(image, None, 0, 255, cv2.NORM_MINMAX)
hist_stretch_opencv = cv2.calcHist([stretched_opencv], [0], None, [256], [0, 256]).flatten()
print("✓ Contrast stretching performed using OpenCV")

stretched_manual = manual_contrast_stretching(image)
hist_stretch_manual = manual_histogram(stretched_manual)
print("✓ Contrast stretching performed using Manual Implementation")

# ============================================================
# VISUALIZATION
# ============================================================
print("\n" + "=" * 60)
print("STEP 6: GENERATING VISUALIZATIONS")
print("=" * 60)

# Figure 1: Original Image Analysis
plt.figure(figsize=(15, 10))

plt.subplot(3, 3, 1)
plt.imshow(image, cmap='gray')
plt.title('Original Image', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(3, 3, 2)
plt.bar(range(256), hist_opencv, color='blue', width=1.0, edgecolor='none')
plt.title('Histogram (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(3, 3, 3)
plt.bar(range(256), hist_manual, color='red', width=1.0, edgecolor='none')
plt.title('Histogram (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(3, 3, 5)
plt.bar(range(256), cumhist_opencv, color='blue', width=1.0, edgecolor='none')
plt.title('Cumulative Histogram (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.subplot(3, 3, 6)
plt.bar(range(256), cumhist_manual, color='red', width=1.0, edgecolor='none')
plt.title('Cumulative Histogram (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig('1_original_analysis.png', dpi=300, bbox_inches='tight')
print("✓ Saved: 1_original_analysis.png")
plt.show()

# Figure 2: Histogram Equalization
plt.figure(figsize=(15, 10))

plt.subplot(2, 3, 1)
plt.imshow(equalized_opencv, cmap='gray')
plt.title('Histogram Equalized (OpenCV)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 3, 2)
plt.bar(range(256), hist_eq_opencv, color='blue', width=1.0, edgecolor='none')
plt.title('Equalized Histogram (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 3)
plt.bar(range(256), np.cumsum(hist_eq_opencv), color='blue', width=1.0, edgecolor='none')
plt.title('Equalized Cumulative (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 4)
plt.imshow(equalized_manual, cmap='gray')
plt.title('Histogram Equalized (Manual)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 3, 5)
plt.bar(range(256), hist_eq_manual, color='red', width=1.0, edgecolor='none')
plt.title('Equalized Histogram (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 6)
plt.bar(range(256), manual_cumulative_histogram(hist_eq_manual), color='red', width=1.0, edgecolor='none')
plt.title('Equalized Cumulative (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig('2_histogram_equalization.png', dpi=300, bbox_inches='tight')
print("✓ Saved: 2_histogram_equalization.png")
plt.show()

# Figure 3: Contrast Stretching
plt.figure(figsize=(15, 10))

plt.subplot(2, 3, 1)
plt.imshow(stretched_opencv, cmap='gray')
plt.title('Contrast Stretched (OpenCV)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 3, 2)
plt.bar(range(256), hist_stretch_opencv, color='blue', width=1.0, edgecolor='none')
plt.title('Stretched Histogram (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 3)
plt.bar(range(256), np.cumsum(hist_stretch_opencv), color='blue', width=1.0, edgecolor='none')
plt.title('Stretched Cumulative (OpenCV)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 4)
plt.imshow(stretched_manual, cmap='gray')
plt.title('Contrast Stretched (Manual)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 3, 5)
plt.bar(range(256), hist_stretch_manual, color='red', width=1.0, edgecolor='none')
plt.title('Stretched Histogram (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Frequency')
plt.grid(alpha=0.3)

plt.subplot(2, 3, 6)
plt.bar(range(256), manual_cumulative_histogram(hist_stretch_manual), color='red', width=1.0, edgecolor='none')
plt.title('Stretched Cumulative (Manual)', fontsize=12)
plt.xlabel('Intensity')
plt.ylabel('Cumulative Frequency')
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig('3_contrast_stretching.png', dpi=300, bbox_inches='tight')
print("✓ Saved: 3_contrast_stretching.png")
plt.show()

# Figure 4: Comparison of All Methods
plt.figure(figsize=(18, 8))

plt.subplot(2, 4, 1)
plt.imshow(image, cmap='gray')
plt.title('Original', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 4, 5)
plt.bar(range(256), hist_manual, color='black', width=1.0, edgecolor='none')
plt.title('Original Histogram', fontsize=10)
plt.grid(alpha=0.3)

plt.subplot(2, 4, 2)
plt.imshow(equalized_opencv, cmap='gray')
plt.title('Equalized (OpenCV)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 4, 6)
plt.bar(range(256), hist_eq_opencv, color='blue', width=1.0, edgecolor='none')
plt.title('Equalized Hist (OpenCV)', fontsize=10)
plt.grid(alpha=0.3)

plt.subplot(2, 4, 3)
plt.imshow(equalized_manual, cmap='gray')
plt.title('Equalized (Manual)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 4, 7)
plt.bar(range(256), hist_eq_manual, color='red', width=1.0, edgecolor='none')
plt.title('Equalized Hist (Manual)', fontsize=10)
plt.grid(alpha=0.3)

plt.subplot(2, 4, 4)
plt.imshow(stretched_manual, cmap='gray')
plt.title('Stretched (Manual)', fontsize=12, fontweight='bold')
plt.axis('off')

plt.subplot(2, 4, 8)
plt.bar(range(256), hist_stretch_manual, color='green', width=1.0, edgecolor='none')
plt.title('Stretched Hist (Manual)', fontsize=10)
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig('4_comparison_all_methods.png', dpi=300, bbox_inches='tight')
print("✓ Saved: 4_comparison_all_methods.png")
plt.show()

# ============================================================
# SUMMARY STATISTICS
# ============================================================
print("\n" + "=" * 60)
print("SUMMARY STATISTICS")
print("=" * 60)
print(f"Original Image - Min: {np.min(image)}, Max: {np.max(image)}, Mean: {np.mean(image):.2f}")
print(
    f"Equalized (OpenCV) - Min: {np.min(equalized_opencv)}, Max: {np.max(equalized_opencv)}, Mean: {np.mean(equalized_opencv):.2f}")
print(
    f"Equalized (Manual) - Min: {np.min(equalized_manual)}, Max: {np.max(equalized_manual)}, Mean: {np.mean(equalized_manual):.2f}")
print(
    f"Stretched (OpenCV) - Min: {np.min(stretched_opencv)}, Max: {np.max(stretched_opencv)}, Mean: {np.mean(stretched_opencv):.2f}")
print(
    f"Stretched (Manual) - Min: {np.min(stretched_manual)}, Max: {np.max(stretched_manual)}, Mean: {np.mean(stretched_manual):.2f}")
print("=" * 60)

print("\n" + "=" * 60)
print("PROCESSING COMPLETE!")
print("=" * 60)
print("\n4 PNG files have been saved in the current directory:")
print("  1. 1_original_analysis.png")
print("  2. 2_histogram_equalization.png")
print("  3. 3_contrast_stretching.png")
print("  4. 4_comparison_all_methods.png")
print("\nThank you for using this program!")
print("=" * 60)