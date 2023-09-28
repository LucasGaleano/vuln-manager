from dataclasses import dataclass, field

@dataclass
class example():

    a:list[int] = field(default_factory=list)


    def __enter__(self):
        print('enter')
        return self
    
    def __exit__(self, type, value, traceback):
        print('exit')
        self.a = []