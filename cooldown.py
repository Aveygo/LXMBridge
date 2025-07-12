import time
from config import config

class AntiSpam:
    def __init__(self):
        self.in_cooldown = False
        self.history = []
        self.min_cooldown = config['advanced']['base_cooldown']
        self.cooldown = self.min_cooldown

    def is_allowed(self):
        return len([i for i in self.history if i > time.time() - self.cooldown]) < 3

    def try_perform_action(self):

        if not self.is_allowed():
            return False

        self.cooldown = max(self.cooldown * 0.7, self.min_cooldown)
        self.history.append(time.time())
        
        self.history = self.history[-10:]

        if not self.is_allowed():
            self.in_cooldown = True
            self.cooldown = (self.cooldown + 1) ** 2
            return False        

        return True

if __name__ == "__main__":
    a = AntiSpam()
    while True:
        input()
        print(a.try_perform_action())