###
# 'Seed' is used to store the seeds for fuzzing process
# 'Seed' attrs - [ M : Message List (Class 'Message')   - to store the list of messages;
#                  R : Response List (String)           - to sotre the list of response messages corresponding to the message list (M) one-to-one by index]
###
class Seed:
    M = []  # Message List - message type
    R = []  # Response List - string

    PR = []  # Probe message response pool - 2d list
    PS = []  # Probe message response similarity scores - 2d list
    PI = []

    isMutated = False

    ClusterList = []

    Snippet = []


    def __init__(self) -> None:
        self.M = []
        self.R = []
        self.PR = []
        self.PS = []
        self.PI = []
        self.isMutated = False
        self.ClusterList = []
        self.Snippet = []



    def append(self, message):
        self.M.append(message)

    def response(self, response):
        self.R.append(response)

    def display(self):
        for i in range(0, len(self.M)):
            print("Message index: ", i + 1)
            # for header in self.M[i].headers:
            #     print(header, " : ", self.M[i].raw[header])
            for msg in self.M[i].raws:
                print('Raw data: ', msg)
            print('Response:')
            print(self.R[i])
            if self.PR and self.PS and self.PI:
                print('Probe Result:')
                print('PI')
                print(self.PI[i])
                print('PR and PS')
                for n in range(len(self.PR[i])):
                    print("(" + str(n) + ") " + self.PR[i][n])
                    print(self.PS[i][n])

                ###


# 'Message' is used to store the message information
# 'Seed' attrs - [ headers : Header List        (String List)                                   - to store all the headers in the message;
#                  raw : Header and corresponding content (Dictionary - { Header : Content } )  - to sotre the list of response messages corresponding to the message list (M) one-to-one by index]
###
class Message:
    # For wingfuzz, no longer headers
    # headers = []  # Header List
    # raw = {}  # Header and corresponding content
    raws = []    # Raw data List

    def __init__(self) -> None:
        # self.headers = []
        # self.raw = {}
        self.raws = []

    def append(self, line) -> None:
        # if ":" in line:
        #     sp = line.split(":")
        #     if sp[0] in self.headers:
        #         print("Error. Message headers '", sp[0], "' is duplicated.")
        #     else:
        #         self.headers.append(sp[0])
        #         self.raw[sp[0]] = line[(line.index(':') + 1):]
        if len(line) != 0:
            self.raws.append(line)