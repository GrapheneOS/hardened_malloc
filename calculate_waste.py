#!/usr/bin/env python3

from sys import argv

size_classes = [
    16, 32, 48, 64, 80, 96, 112, 128,
    160, 192, 224, 256,
    320, 384, 448, 512,
    640, 768, 896, 1024,
    1280, 1536, 1792, 2048,
    2560, 3072, 3584, 4096,
    5120, 6144, 7168, 8192,
    10240, 12288, 14336, 16384,
    20480, 24576, 28672, 32768,
    40960, 49152, 57344, 65536,
    81920, 98304, 114688, 131072,
]

size_class_slots = [
    256, 128, 85, 64, 51, 42, 36, 64,
    51, 64, 54, 64,
    64, 64, 64, 64,
    64, 64, 64, 64,
    16, 16, 16, 16,
    8, 8, 8, 8,
    8, 8, 8, 8,
    6, 5, 4, 4,
    2, 2, 2, 2,
    1, 1, 1, 1,
    1, 1, 1, 1,
]

fragmentation = [100 - 1 / 16 * 100]

for i in range(len(size_classes) - 1):
    size_class = size_classes[i + 1]
    worst_case = size_classes[i] + 1
    used = worst_case / size_class
    fragmentation.append(100 - used * 100);

def page_align(size):
    return (size + 4095) & ~4095

print("| ", end="")
print("size class", "worst case internal fragmentation", "slab slots", "slab size", "internal fragmentation for slabs", sep=" | ", end=" |\n")
print("| ", end='')
print("-", "-", "-", "-", "-", sep=" | ", end=" |\n")
for size, slots, fragmentation in zip(size_classes, size_class_slots, fragmentation):
    used = size * slots
    real = page_align(used)
    print("| ", end='')
    print(size, f"{fragmentation:.4}%", slots, real, str(100 - used / real * 100) + "%", sep=" | ", end=" |\n")

if len(argv) < 2:
    exit()

max_bits = 256
max_page_span = 16

print()

print("maximum bitmap size is {}-bit".format(max_bits))
print("maximum page span size is {} ({})".format(max_page_span, max_page_span * 4096))

for size_class in size_classes:
    choices = []
    for bits in range(1, max_bits + 1):
        used = size_class * bits
        real = page_align(used)
        if real > 65536:
            continue
        pages = real / 4096
        efficiency = used / real * 100
        choices.append((bits, used, real, pages, efficiency))

    choices.sort(key=lambda x: x[4], reverse=True)

    print()
    print("size_class:", size_class)
    for choice in choices[:10]:
        print(choice)
