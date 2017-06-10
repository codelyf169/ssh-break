import csv
import random
with open('eggs.csv', 'wb') as csvfile: 
        spamwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(["IP_address","Time_arrival","No_of_Attempts","Success","Type"])
        for i in range(0,10000):
            ip=str(random.randrange(10,223))+"."+str(random.randrange(10,223))+"."+str(random.randrange(10,223))+"."+str(random.randrange(10,223))
            time=random.uniform(0,8)
            attempts=random.randrange(1,15)
            Success=random.randrange(0,2)
            if(attempts < 5 and time > 1  and Success == 1):
                type="Legit"
                spamwriter.writerow([ip,time,attempts,Success,type])
            elif(time < 2 and attempts > 2):
                type="Dictionary"
                spamwriter.writerow([ip,time,attempts,Success,type])
            elif(time > 1 and attempts > 4):
                type="Anonymous"
                spamwriter.writerow([ip,time,attempts,Success,type])
                
                