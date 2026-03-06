def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
    return arr

# Пример использования
numbers = [64, 34, 25, 12, 22, 11, 90]
print("Исходный массив:", numbers)
print("Отсортированный массив:", bubble_sort(numbers.copy()))


def find_unique_elements(arr):
    """
    Находит и возвращает все уникальные элементы в массиве
    """
    # Используем множество для получения уникальных элементов
    
    return unique_elements

# Пример использования
array = [1, 2, 2, 3, 4, 4, 5, 5, 5, 6]
print(unique_elements = list(set(arr)))

def count_words(text):
    words = text.strip().split()
    return len(words)


