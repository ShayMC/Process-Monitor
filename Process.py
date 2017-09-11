

def sort(array):
    for i in range(1, len(array)):
        j = i
        while j > 0 and array[j].get_pid() < array[j - 1].get_pid():
            array[j], array[j - 1] = array[j - 1], array[j]
            j = j - 1
    return array


def binary_search(sequence, value):
    lo, hi = 0, len(sequence) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if sequence[mid].get_pid() < value:
            lo = mid + 1
        elif value < sequence[mid].get_pid():
            hi = mid - 1
        else:
            return mid
    return None


class Process:
    def __init__(self, name, pid, ram):
        self.name = name
        self.pid = pid
        self.ram = ram
        self.children = []

    def get_name(self):
        return self.name

    def get_ram(self):
        return self.ram

    def get_pid(self):
        return self.pid

    def get_children(self):
        return self.children

    def add_child(self, child):
        self.children.append(child)
        self.children = sort(self.children)

    def check(self, children):
        if binary_search(children, self.get_pid()) is not None:
            return True
        return False
