def ch1():
    print "try later"

def ch2():
    print "try later"

def ch3():
    print "try later"

def ch4():
    print "try later"

def ch5():
    print "try later"

def ch6():
    print "try later"

def ch7():
    print "try later"

def ch8():
    print "try later"


def init():
    choice = raw_input("enter [1-8] to select challange: ")
    methodSwitcher = {
        "1": ch1,
        "2": ch2,
        "3": ch3,
        "4": ch4,
        "5": ch5,
        "6": ch6,
        "7": ch7,
        "8": ch8,
    }
    methodSwitcher.get(choice, ch1)()

init()