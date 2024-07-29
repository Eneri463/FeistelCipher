from Crypto.Util import number
import numpy as np
import PySimpleGUI as sg
import random
import matplotlib.pyplot as plt

def graph(res, text, name):
    

    # ось х
    x = np.arange(1, 17, 1)
    
    # окно с графиками
    fig = plt.figure(figsize = (7, 2))
    
    plt.xlabel('Раунд')
    plt.ylabel('Количество отличий')
    plt.bar(x, res)
    
    plt.title(text)
    plt.savefig(name)
    
    plt.close(fig)

# -----------------------------------------------------------------------------
# считаем количество несовпадающих битов
def getNumberOfChanges(res1, res2):
    
    res = []
    for i in range(len(res1)):
        a = 0
        for j in range(64):
            if res1[i][j] != res2[i][j]:
                a = a+1
        res.append(a)
    return res
            

# -----------------------------------------------------------------------------
# получение подключей первым методом
def getVi1(Key, l):
    
    keyNew = ""
    
    for i in range(len(Key)):
        keyNew = keyNew + Key[i]
    
    lenKey = len(keyNew)
    Vi = []
    
    for i in range(16):
        
        flag = ""
        n = i
        
        while len(flag) < l:
            
            flag = flag + keyNew[n]
            
            n = n + 1
            
            if n == lenKey:
                n = 0
        
        Vi.append(flag)
        
    return Vi

# -----------------------------------------------------------------------------
# получение подключей вторым методом
def getVi2(Key):
    
    Keyi = getVi1(Key, 8)
    Vi = []
    
    for i in range(16):
        
        Vi.append(keyGeneration(32, 1, int(Keyi[i],2)))
    
    return Vi

# -----------------------------------------------------------------------------
# определяем левую и правую части сообщения
def leftRight(M):
    
    Left = 0
    Right = 0
    
    flag = ""
    
    for i in range(4):
        flag = flag + M[i]
    
    Left = int(flag, 2)
    
    flag = ""
    
    for i in range(4, len(M)):
        flag = flag + M[i]
    
    Right = int(flag, 2)
    
    return Left, Right
        

# -----------------------------------------------------------------------------
# сеть Фейстеля
# typeWork: 1 - шифрование, 2 - дешифрование
# typeKi: 1 - первый тип подключа, 2 - второй тип подключа
# typeF: если 1, то F(Vi) = Vi, если 2, то F(Vi,X) = S(X) XOR Vi
# M - массив из восьми символов исходного сообщения, представленных в двоичном формате
# Key - массив из восьми 8битных двоичных последовательностей
# needRes - нужно ли возвращать прмоежуточные значения шифротекста

def feistelsNetwork(typeWork, typeKi, typeF, M, Key, needRes = 1):
    
    Vi = [] # подключи i-тых рангов
    res = [] # промежуточные значения сообщений
    
    if typeKi == 1:
        Vi = getVi1(Key, 32)
    else:
        Vi = getVi2(Key)
    
    if typeWork == 2:
        Vi.reverse()
    
    # определяем левую и правую части сообщения
    Left, Right =  leftRight(M)
    
    # 32-битная последовательность, полученная 16 разрядным скремблером
    S = int(keyGeneration(32, 2),2)
    
    # определение вида образующей функции
    if typeF == 1:
        F = lambda x, y : int(y, 2)
    else:
        F = lambda x, y: S ^ x ^ int(y,2)
    
    a = ""
    b = ""
    
    # проходим 16 раундов
    for i in range(16):
        
        flag = Left
        Left = F(Left,Vi[i])^Right
        Right = flag
    
        a = str(bin(Right))[2:]
        while (len(a)<32):
            a = '0' + a
        
        b = str(bin(Left))[2:]
        
        while (len(b)<32):
            b = '0' + b
        
        res.append(a+b)
    
    if needRes == 1:
        return a + b
    else:
        return a+b, res
    
# -----------------------------------------------------------------------------
# скремблер x^8+x^1+1
def  LFSR1(startValue):
    
    startValue = (((startValue^(startValue >> 1))&0b1)<<7)|(startValue >> 1)
    
    return startValue & 0b1, startValue

# -----------------------------------------------------------------------------
# скремблер x^16+x^15+x^1+1
def  LFSR2(startValue):
    
    startValue = (((startValue^(startValue >> 1)^(startValue >> 15))&0b1)<<15)|(startValue >> 1)
    
    return startValue & 0b1, startValue

# -----------------------------------------------------------------------------
# генерация случайного ключа определённой длины, используя скремблер
def keyGeneration(l, typeLFSR, startValue = 127):
    
    res = startValue & 0b1
    
    if typeLFSR == 1:
        
        for _ in range(l-1):
            _, startValue = LFSR1(startValue)
            res = (res << 1) | (startValue & 0b1)
  
    else:
        
        for _ in range(l-1):
            _, startValue = LFSR2(startValue)
            res = (res << 1) | (startValue & 0b1)
    
    key = str(bin(res))[2:]
    
    # учитываем случай, когда первые сгенерированные цифры случайной 
    # последовательности - нули
    while (len(key)<l):
        key = '0' + key
    
    
    return key 

# -----------------------------------------------------------------------------
# замена бита под номером n в сообщении M
def changeBit(n, M):
    
    n = n-1
    
    nByte = int(n/8) # номер изменяемого байта
    nBit = n%8 # номер изменяемого бита в байте
    
    changeMessage = M[nByte]
    res = ""
    
    for i in range(8):
        if i != nBit:
            res = res +  changeMessage[i]
        else:
            if changeMessage[i] == "0":
                res = res + "1"
            else:
                res = res + "0"
    M[nByte] = res
    
    return M
    
    

# -----------------------------------------------------------------------------
# сохранение зашифрованного текста в файл
def saveM(M):
    
    with open("M.txt", "w", encoding="utf-8") as f:
        f.write(M)

# -----------------------------------------------------------------------------
# сохранение ключа в файл
def saveKey(key):
    
    with open("Key.txt", "w", encoding="utf-8") as f:
        f.write(key)

# -----------------------------------------------------------------------------
# сохранение начального состояния в файл
def saveState(State):
    
    with open("State.txt", "w", encoding="utf-8") as f:
        f.write(State)

# -----------------------------------------------------------------------------
# сохранение шифротекста в файл
def saveC(C):
    
    with open("C.txt", "w", encoding="utf-8") as f:
        f.write(C)

# -----------------------------------------------------------------------------
# проверка, корректно ли задан двоичный текст
def check2(M):
    
    flag = 0
    
    if M[0] == ' ':
        return False, 'Текст не соответствует выбранному формату (проверьте пробелы)'
    
    for i in range(len(M)):
        
        if M[i] != '1' and M[i] != '0':
            
            if M[i] != ' ':
                return False, 'Текст не соответствует выбранному формату'
            else:
                if M[i-1] == ' ':
                    return False, 'Текст не соответствует выбранному формату (проверьте пробелы)'
                else:
                    flag = -1
        
        flag = flag + 1
        
        if flag == 9:
            return False, 'Каждый сивмол кодируется 8-ью битами'
    
    return True, 'Ок'

# -----------------------------------------------------------------------------
# проверка, корректно ли задан шестнадцатиричный текст
def check16(M):
    
    flag = 0
    
    if M[0] == ' ':
        return False, 'Текст не соответствует выбранному формату (проверьте пробелы)'
    
    for i in range(len(M)):
        
        if (M[i] < 'A' or M[i] > 'F') and (M[i] < '0' or M[i] > '9'):
            
            if M[i] != ' ':
                return False, 'Текст не соответствует выбранному формату'
            else:
                if M[i-1] == ' ':
                    return False, 'Текст не соответствует выбранному формату (проверьте пробелы)'
                else:
                    flag = -1
        
        flag = flag + 1
        
        if flag == 3:
            return False, 'Максимальное значение FF'
    
    return True, 'Ок'


# -----------------------------------------------------------------------------
# проверка отсутствия кириллицы и символов, номер которых больше 255
def checkSymbol(M):
    
    for i in range(len(M)):
        
        if ord(M[i]) > 255:
            return False, 'Текст не должен содержать кириллицу'
    
    return True, 'Ок'

# -----------------------------------------------------------------------------
# проверка корректного заполнения номера бита
def checkNumber(n):
    
    for i in range(len(n)):
        if (n[i] < '0' or n[i] > '9'):
            return False, 'Число задано некорректно'
    
    return True, 'Ок'

# -----------------------------------------------------------------------------
# перевод текста из 16-ричной в 2-ичную систему
def from16To2(M):
    
    res = []
    
    for i in range(len(M)):
        
        a = bin(int(M[i],16))[2:]
        
        while (len(a)<8):
            a = '0' + a
        
        res.append(a)
    
    return res

# -----------------------------------------------------------------------------
# перевод текста из 2-ичную в 16-ричную систему
def from2To16(M):
    
    res = []
    
    for i in range(len(M)):
        
        a = hex(int(M[i],2)).upper()[2:]
        
        res.append(a)
    
    return res

# -----------------------------------------------------------------------------
# перевод текста из символьного в 2-ичный формат
def fromSymbolTo2(M):
    
    res = []
    
    for i in range(len(M)):
        
        a = bin(ord(M[i]))[2:]
        
        while (len(a)<8):
            a = '0' + a
        
        res.append(a)
    
    return res

# -----------------------------------------------------------------------------
# перевод текста из 2-ичного формата в символьный
def from2ToSymbol(M):
    
    res = ""
    
    for i in range(len(M)):
        
        a = chr(int(M[i],2))
        
        res = res + a
    
    return res

# -----------------------------------------------------------------------------
# разделяем каждые 8 битов 2-ичного представления(если требуется)
def newRepresent(key):
    
    res = []
    a = ''
    flag = 0
    
    for i in range(len(key)):
            
        a = a + key[i]
        flag = flag+1
            
        if flag == 8:
                
            flag = 0
            res.append(a)
            a = ''
    
    return res

#------------------------------------------------------------------------------
# наибольший общий делитель двух чисел
def NOD(a, b):
    
    while a != b:
        if a > b:
            a = a - b
        else:
            b = b - a        
            
    return a

#------------------------------------------------------------------------------
# генерация простых чисел
def prime(n):
    
    # генерируем простое число x пока x mod 4 != 3
    
    while True:
        x = number.getPrime(n)
        if  x % 4 == 3:
            return x

#------------------------------------------------------------------------------
# выбираем стартовое целое число s
def getS(N):
    
    while True:
        s = random.randint(1,N-1)
        
        if NOD(s, N) == 1:
            return s

#------------------------------------------------------------------------------
# алгоритм BBS для генерации ключа
def BBS(m):
    
    bits = 160
    
    # ----------
    # генерируем простые числа p и q
    
    p = prime(bits)
    
    q = p
    
    # проверяем, чтобы x и y не были одинковыми числами
    while (p == q):
        q = prime(bits)
    
    N = p*q
    
    # генерируем целое число s
    s = getS(N)
    
    # задаём u0
    ui = s**2 % N
    
    x = ""
    
    # ----------
    # формируем выходную последовательность
    
    for i in range(m):
        
        ui =  ui**2 % N
        
        # двоичное представление ui
        bui = bin(ui)
        
        # запоминаем младший бит двоичного представления ui
        x = x + bui[len(bui)- 1]
    
    return x

# -----------------------------------------------------------------------------
# интерфейс
def main():
    
    sg.theme('DefaultNoMoreNagging')


    one = [
                    [sg.Text('________________________________________________________________________________________________________________')],
                    [sg.Text('Сообщение (M)')],
                    [sg.Text('Формат сообщения'), sg.Radio("2-ичный", "type2", key='2M', default=True), sg.Radio("16-ричный", "type2", key='16M'), sg.Radio("символьный", "type2", key='symbolM')],
                    [sg.Multiline(size=(110, 5), key="M")],
                    [sg.Text('Ключ (Key) '), sg.Button('Сгенерировать', key ='ok1')],
                    [sg.Text('Формат ключа'), sg.Radio("2-ичный", "type1", key='2K', default=True), sg.Radio("16-ричный", "type1", key='16K'), sg.Radio("символьный", "type1", key='symbolK')],
                    [sg.Multiline(size=(110, 5), key="Key")],
                    [sg.Text('Результат шифрования'), sg.Button('Получить', key ='ok2')],
                    [sg.Text('Способ получения подключа: '), sg.Combo(['Первый','Второй'], default_value='Первый',key='board'), sg.Text('Образующая функция: '), sg.Combo(['F(Vi) = Vi','F(Vi,X) = S(X) XOR Vi'], default_value='F(Vi) = Vi',key='board1')],
                    [sg.Text('Формат шифротекста'), sg.Radio("2-ичный", "type9", key='2C3', default=True), sg.Radio("16-ричный", "type9", key='16C3'), sg.Radio("символьный", "type9", key='symbolC3')],
                    [sg.Output(size=(110, 5),key='result1')],
                    [sg.Text('________________________________________________________________________________________________________________')]
                ]
    
    two = [
                    [sg.Text('________________________________________________________________________________________________________________')],
                    [sg.Text('Зашифрованный текст (C)')],
                    [sg.Text('Формат сообщения'), sg.Radio("2-ичный", "type3", key='2C', default=True), sg.Radio("16-ричный", "type3", key='16C'), sg.Radio("символьный", "type3", key='symbolC')],
                    [sg.Multiline(size=(110, 5), key="C")],
                    [sg.Text('Ключ (Key) '), sg.Button('Сгенерировать', key ='ok3')],
                    [sg.Text('Формат ключа'), sg.Radio("2-ичный", "type", key='2', default=True), sg.Radio("16-ричный", "type", key='16'), sg.Radio("символьный", "type", key='symbol')],
                    [sg.Multiline(size=(110, 5), key="Key2")],
                    [sg.Text('Результат дешифрования'), sg.Button('Получить', key ='ok4')],
                    [sg.Text('Способ получения подключа: '), sg.Combo(['Первый','Второй'], default_value='Первый',key='board2'), sg.Text('Образующая функция: '), sg.Combo(['F(Vi) = Vi','F(Vi,X) = S(X) XOR Vi'], default_value='F(Vi) = Vi',key='board3')],
                    [sg.Text('Формат расшифрованного текста:'), sg.Radio("2-ичный", "type10", key='2C4', default=True), sg.Radio("16-ричный", "type10", key='16C4'), sg.Radio("символьный", "type10", key='symbolC4')],
                    [sg.Output(size=(110, 5),key='result2')],
                    [sg.Text('________________________________________________________________________________________________________________')]
                ]
    
    three = [
                    [sg.Text('________________________________________________________________________________________________________________')],
                    [sg.Text('Исходный текст')],
                    [sg.Text('Формат текста'), sg.Radio("2-ичный", "type6", key='2C1', default=True), sg.Radio("16-ричный", "type6", key='16C1'), sg.Radio("символьный", "type6", key='symbolC1')],
                    [sg.Multiline(size=(110, 5), key="text")],
                    [sg.Text('Текст в другом формате'), sg.Button('Сгенерировать', key ='ok5')],
                    [sg.Text('Перевод в:'), sg.Radio("2-ичный", "type7", key='2C2', default=True), sg.Radio("16-ричный", "type7", key='16C2'), sg.Radio("символьный", "type7", key='symbolC2')],
                    [sg.Output(size=(110, 5),key='result3')],
                    [sg.Text('________________________________________________________________________________________________________________')]
                ]
    
    four = [
                    [sg.Text('________________________________________________________________________________________________________________')],
                    [sg.Text('Проверка ловинного эффекта')],
                    [sg.Text('Сообщение (M) - 8 байт в двоичном формате')],
                    [sg.Input(size=(95, 5), key="lavM"), sg.Button('Сгенерировать', key ='ok6') ],
                    [sg.Text('Ключ (Key) - 8 байт в двоичном формате')],
                    [sg.Input(size=(95, 5), key="lavKey"), sg.Button('Сгенерировать', key ='ok7')],
                    [sg.Text('Номер изменяемого бита: '),sg.Input(size=(10, 5), key="lavBit"),sg.Text('Изменять бит в: '), sg.Radio("ключе", "numBit", key='keyBit', default=True), sg.Radio("сообщении", "numBit", key='mBit')],
                    [sg.Button('Проверить', key ='ok8')],
                    [sg.Text('________________________________________________________________________________________________________________')]
                ]
    
    tab_group_layout = [[sg.TabGroup([[sg.Tab('Шифрование', one, key='-TAB1-'), sg.Tab('Дешифрование', two, key='-TAB2-'),sg.Tab('Изменение формата', three, key='-TAB3-'),sg.Tab('Лавинный эффект', four, key='-TAB4-')]])]]
    
    window = sg.Window('Лабораторная 2', tab_group_layout)
    
    
    while True:
        
        event, values = window.read()
        
        if event in (None, 'Exit'):
            break
        
# -----------------------------------------------------------------------------
        # генерация ключа (шифрование)
        elif  event == 'ok1':
            
            key = "" # значение ключа
            fKey = 0 # формат ключа
            
            if values['2K'] == True:
                fKey = 1 # 2-ичное представление
            elif values['16K'] == True:
                fKey = 2 # 16-ричное представление
            elif values['symbolK'] == True:
                fKey = 3 # символьное представление
            
            key = newRepresent(BBS(32))
                
            # переводим ключ в нужный формат
            if fKey == 2:
                key = from2To16(key)
            elif fKey == 3:
                key = from2ToSymbol(key)
                        
            if fKey == 1 or fKey == 2:
                window['Key'].update(' '.join(key))
            else:
                window['Key'].update(key)

# -----------------------------------------------------------------------------
        # шифрование
        elif event == 'ok2':
            
            M = values['M'] # текст шифруемого сообщения
            C = "" # результат шифрования
            key = values['Key'] # значение ключа
            lenM = 0 # длина сообщения
            fM = 0 # формат сообщения
            fKey = 0 # формат ключа
            fC = 0 # формат шифротекста
            textError = "" # текст ошибки
            flag = True # вспомогательная переменная
            typeKey = 0 # тип подключей
            typeF = 0 # тип функции
                
            if values['2M'] == True:
                fM = 1 # 2-ичное представление
            elif values['16M'] == True:
                fM = 2 # 16-ричное представление
            elif values['symbolM'] == True:
                fM = 3 # символьное представление
                
            if values['2K'] == True:
                fKey = 1 # 2-ичное представление
            elif values['16K'] == True:
                fKey = 2 # 16-ричное представление
            elif values['symbolK'] == True:
                fKey = 3 # символьное представление
            
            if values['2C3'] == True:
                fC = 1 # 2-ичное представление
            elif values['16C3'] == True:
                fC = 2 # 16-ричное представление
            elif values['symbolC3'] == True:
                fC = 3 # символьное представление
                
            if values['board'] == 'Первый':
                 typeKey = 1
            else:
                 typeKey = 2
            
            if values['board1'] == 'F(Vi) = Vi':
                typeF = 1
            else:
                typeF = 2
            
            
            
            # ----------------------------------- проверка шифруемого сообщения
            if M == "":
                sg.popup_ok("Сначала введите сообщение, которое необходимо зашифровать")
            else:
                # проверяем, в нужном ли формате задано сообщение
                if fM == 1:
                    flag, textError = check2(M)
                elif fM == 2:
                    flag, textError = check16(M)
                elif fM ==3:
                    flag, textError = checkSymbol(M)
                
                if flag == False:
                    sg.popup_ok(textError)
                else:
                    
                    Mnew = [] # сообщение, разбитое на символы (необходимо, если формат не символьный)
                    
                    # определяем длину сообщения
                    if fM != 3:
                        Mnew = M.split()
                        lenM = len(Mnew)
                    else:
                        Mnew = M
                        lenM = len(M)
                    
                    # текст должен разбиваться на блоки по 64 бита
                    if lenM % 8 != 0:
                        sg.popup_ok("Количество символов должно быть кратно 8 (у вас " + str(lenM) + ")")
                    else:
                    
                        # ------------------------------------------ проверка ключа
                        if key == "":
                            sg.popup_ok("Введите или сгенирируйте ключ")
                        else:
                            
                            # проверяем, в нужном ли формате задан ключ
                            if fKey == 1:
                                flag, textError = check2(key)
                                textError = textError + " (речь о ключе)"
                            elif fKey == 2:
                                flag, textError = check16(key)
                                textError = textError + " (речь о ключе)"
                            
                            if flag == False:
                                sg.popup_ok(textError)
                                
                            else:
                                
                                keyNew = []
                                
                                # определяем длину ключа
                                if fKey != 3:
                                    keyNew = key.split()
                                    lenKey = len(keyNew)
                                else:
                                    keyNew = key
                                    lenKey = len(key)
                                
                                
                                # проверяем длину ключа
                                if lenKey < 4:
                                    
                                    sg.popup_ok("Длина ключа должна быть не меньше 4 байт")
                                
                                else:
                                    
                                    # ----------------------- генерируем шифротекст
                                    
                                    # изменяем тип шифруемого сообщения
                                    if fM == 2:
                                        Mnew = from16To2(Mnew)
                                    elif fM == 3:
                                        Mnew = fromSymbolTo2(Mnew)
                                    
                                    # изменяем тип ключа
                                    if fKey == 2:
                                        keyNew = from16To2(keyNew)
                                    elif fKey  == 3:
                                        keyNew = fromSymbolTo2(keyNew)
                                    
                                    # вычисляем шифротекст
                                    C = []
                                    for i in range(int(lenM/8)):
                                        C = C + newRepresent(feistelsNetwork(1, typeKey, typeF, Mnew[i*8:(i+1)*8], keyNew))
                                    
                                    if fC == 2:
                                        window['result1'].update(' '.join(from2To16(C)))
                                    elif fC == 3:
                                        window['result1'].update(from2ToSymbol(C))
                                    else:
                                        window['result1'].update(' '.join(C))
                                
                                    
                                
# -----------------------------------------------------------------------------
        # генерация ключа (дешифрование)
        elif  event == 'ok3':
            
            key = "" # значение ключа
            fKey = 0 # формат ключа
            
            if values['2'] == True:
                fKey = 1 # 2-ичное представление
            elif values['16'] == True:
                fKey = 2 # 16-ричное представление
            elif values['symbol'] == True:
                fKey = 3 # символьное представление
            
            key = newRepresent(BBS(32))
                
            # переводим ключ в нужный формат
            if fKey == 2:
                key = from2To16(key)
            elif fKey == 3:
                key = from2ToSymbol(key)
                        
            if fKey == 1 or fKey == 2:
                window['Key2'].update(' '.join(key))
            else:
                window['Key2'].update(key)
                                
# -----------------------------------------------------------------------------
        # дешифрование
        elif event == 'ok4':
            
            C = values['C'] # дешифруемое сообщение
            M = "" # результат шифрования
            key = values['Key2'] # значение ключа
            lenC = 0 # длина сообщения
            fM = 0 # формат сообщения
            fKey = 0 # формат ключа
            fC = 0 # формат шифротекста
            textError = "" # текст ошибки
            flag = True # вспомогательная переменная
            typeKey = 0 # тип подключей
            typeF = 0 # тип функции
                
            if values['2C4'] == True:
                fM = 1 # 2-ичное представление
            elif values['16C4'] == True:
                fM = 2 # 16-ричное представление
            elif values['symbolC4'] == True:
                fM = 3 # символьное представление
                
            if values['2'] == True:
                fKey = 1 # 2-ичное представление
            elif values['16'] == True:
                fKey = 2 # 16-ричное представление
            elif values['symbol'] == True:
                fKey = 3 # символьное представление
            
            if values['2C'] == True:
                fC = 1 # 2-ичное представление
            elif values['16C'] == True:
                fC = 2 # 16-ричное представление
            elif values['symbolC'] == True:
                fC = 3 # символьное представление
                
            if values['board2'] == 'Первый':
                 typeKey = 1
            else:
                 typeKey = 2
            
            if values['board3'] == 'F(Vi) = Vi':
                typeF = 1
            else:
                typeF = 2
            
            
            
            # ----------------------------------- проверка шифруемого сообщения
            if C == "":
                sg.popup_ok("Сначала введите сообщение, которое необходимо дешифровать")
            else:
                # проверяем, в нужном ли формате задано сообщение
                if fC == 1:
                    flag, textError = check2(C)
                elif fC == 2:
                    flag, textError = check16(C)
                elif fC ==3:
                    flag, textError = checkSymbol(C)
                
                if flag == False:
                    sg.popup_ok(textError)
                else:
                    
                    Cnew = [] # сообщение, разбитое на символы (необходимо, если формат не символьный)
                    
                    # определяем длину сообщения
                    if fC != 3:
                        Cnew = C.split()
                        lenC = len(Cnew)
                    else:
                        Cnew = C
                        lenC = len(C)
                    
                    # текст должен разбиваться на блоки по 64 бита
                    if lenC % 8 != 0:
                        sg.popup_ok("Количество символов шифротекста должно быть кратно 8 (у вас " + str(lenC) + ")")
                    else:
                    
                        # ------------------------------------------ проверка ключа
                        if key == "":
                            sg.popup_ok("Введите или сгенирируйте ключ")
                        else:
                            
                            # проверяем, в нужном ли формате задан ключ
                            if fKey == 1:
                                flag, textError = check2(key)
                                textError = textError + " (речь о ключе)"
                            elif fKey == 2:
                                flag, textError = check16(key)
                                textError = textError + " (речь о ключе)"
                            
                            if flag == False:
                                sg.popup_ok(textError)
                                
                            else:
                                
                                keyNew = []
                                
                                # определяем длину ключа
                                if fKey != 3:
                                    keyNew = key.split()
                                    lenKey = len(keyNew)
                                else:
                                    keyNew = key
                                    lenKey = len(key)
                                
                                
                                # проверяем длину ключа
                                if lenKey < 4:
                                    sg.popup_ok("Длина ключа должна быть не меньше 4 байт")
                                else:
                                    
                                    # ----------------------- генерируем шифротекст
                                    
                                    # изменяем тип шифруемого сообщения
                                    if fC == 2:
                                        Cnew = from16To2(Cnew)
                                    elif fC == 3:
                                        Cnew = fromSymbolTo2(Cnew)
                                    
                                    # изменяем тип ключа
                                    if fKey == 2:
                                        keyNew = from16To2(keyNew)
                                    elif fKey  == 3:
                                        keyNew = fromSymbolTo2(keyNew)
                                    
                                    # вычисляем шифротекст
                                    M = []
                                    for i in range(int(lenM/8)):
                                        M = M + newRepresent(feistelsNetwork(2, typeKey, typeF, Cnew[i*8:(i+1)*8], keyNew))
                                    
                                    if fM == 2:
                                        window['result2'].update(' '.join(from2To16(M)))
                                    elif fM == 3:
                                        window['result2'].update(from2ToSymbol(M))
                                    else:
                                        window['result2'].update(' '.join(M))
                                
                                
# -----------------------------------------------------------------------------
        # смена формата
        elif event == 'ok5':
            
            M = values['text'] # текст, для которого меняем формат
            fM = 0 # формат изменяемого текста
            resText = "" # текст с изменённым форматом
            fT = 0 # желаемый формат
            flag = True # вспомогательная переменная
            
            
            
            if values['2C1'] == True:
                fM = 1 # 2-ичное представление
            elif values['16C1'] == True:
                fM = 2 # 16-ричное представление
            elif values['symbolC1'] == True:
                fM = 3 # символьное представление
                
            
            if values['2C2'] == True:
                fT = 1 # 2-ичное представление
            elif values['16C2'] == True:
                fT = 2 # 16-ричное представление
            elif values['symbolC2'] == True:
                fT = 3 # символьное представление
            
            
            # ----------------------------------- проверка изменяемого сообщения
            if M == "":
                sg.popup_ok("Сначала введите текст, для которого меняется формат")
            else:
                # проверяем, в нужном ли формате задано сообщение
                if fM == 1:
                    flag, textError = check2(M)
                elif fM == 2:
                    flag, textError = check16(M)
                elif fM ==3:
                    flag, textError = checkSymbol(M)
                
                if flag == False:
                    sg.popup_ok(textError)
                else:
                # ----------------------------------- изменение формата
                    
                    Mnew = [] # сообщение, разбитое на символы (необходимо, если формат не символьный)
                    
                    if fM != 3:
                        Mnew = M.split()
                    else:
                        Mnew = M
                    
                    if fM == 2:
                        resText = from16To2(Mnew)
                    elif fM == 3:
                        resText = fromSymbolTo2(Mnew)
                    else:
                        resText = Mnew
                    
                    if fT == 2:
                        window['result3'].update(' '.join(from2To16(resText)))
                    elif fT == 3:
                        window['result3'].update(from2ToSymbol(resText))
                    else:
                        window['result3'].update(' '.join(resText))
                    

# -----------------------------------------------------------------------------
        # генерация блока текста
        elif event == 'ok6':
            
            key = "" # значение ключа
            fKey = 0 # формат ключа
            
            key = newRepresent(BBS(64))

            window['lavM'].update(' '.join(key))

# -----------------------------------------------------------------------------        
        # генерация ключа
        elif event == 'ok7':
            
            key = "" # значение ключа
            fKey = 0 # формат ключа
            
            key = newRepresent(BBS(64))

            window['lavKey'].update(' '.join(key))

# -----------------------------------------------------------------------------
        # генерация блока текста
        elif event == 'ok8':
            
            bitNumber = values['lavBit'] # номер иземняемого бита
            M = values['lavM'] # блок сообщения
            Key = values['lavKey'] # блок ключа
            
            if M == "" or Key =="" or bitNumber=="":
                sg.popup_ok("Заполните все пустые поля")
            else:
                
                # проверяем, в нужном ли формате задано сообщение
                flag, _ = check2(M)
                
                if flag == False:
                    sg.popup_ok("Сообщение должно быть в двоичном формате")
                else:
                    
                    Mnew = [] # сообщение в виде списка (один элемент - один символ)
                    Mnew = M.split()
                    
                    # текст должен быть блоком в 64 бита
                    if len(Mnew) % 8 != 0:
                        sg.popup_ok("Длина сообщения должна быть равна 8 символам (у вас " + str(len(Mnew)) + ")")
                    else:
                        # проверяем, в нужном ли формате задан ключ
                        flag, _ = check2(Key)
                        
                        if flag == False:
                            sg.popup_ok("Ключ должен быть в двоичном формате")
                        else:
                            
                            keyNew = [] # ключ в виде списка (один элемент - один символ)
                            keyNew = Key.split()
                            
                            # проверяем, соответствует ли длина ключа длине сообщения
                            if len(keyNew) < 4:
                                sg.popup_ok("Длина ключа должна быть равна 8 символам (64 бита)")
                            else:
                                
                                # проверяем, корректно ли задан номер изменяемого бита
                                flag, _ = checkNumber(bitNumber)
                                
                                if flag == False:
                                    sg.popup_ok("Номер бита задан некорректно")
                                else:
                                    
                                    bitN =  int(bitNumber)
                                    
                                    if bitN == 0 or (values['keyBit'] == True and len(keyNew)*8 < bitN) or (values['keyBit'] == False and bitN > 64):
                                        sg.popup_ok("Нумерация битов начинается с 1, а максимальный номер изменяемого бита не должен превышать длину ключа/сообщения")
                                    else:
                                        
                                        changeM = Mnew.copy() # сообщение с заменённым битом
                                        changeKey = keyNew.copy() # ключ с заменённым битом
                                        
                                        # заменяем бит в ключе или в сообщении
                                        if values['keyBit'] == True:
                                            changeBit(bitN, changeKey)
                                        else:
                                            changeBit(bitN, changeM)
                                        
                                        _, res11 =  feistelsNetwork(1, 1, 1, Mnew, keyNew, 2)
                                        _, res12 =  feistelsNetwork(1, 1, 1, changeM, changeKey, 2)
                                        
                                        _, res21 =  feistelsNetwork(1, 1, 2, Mnew, keyNew, 2)
                                        _, res22 =  feistelsNetwork(1, 1, 2, changeM, changeKey, 2)
                                        
                                        _, res31 =  feistelsNetwork(1, 2, 1, Mnew, keyNew, 2)
                                        _, res32 =  feistelsNetwork(1, 2, 1, changeM, changeKey, 2)
                                        
                                        _, res41 =  feistelsNetwork(1, 2, 2, Mnew, keyNew, 2)
                                        _, res42 =  feistelsNetwork(1, 2, 2, changeM, changeKey, 2)
                                        
                                        res1 = getNumberOfChanges(res11, res12)
                                        res2 = getNumberOfChanges(res21, res22)
                                        res3 = getNumberOfChanges(res31, res32)
                                        res4 = getNumberOfChanges(res41, res42)
                                        
                                        graph(res1, "Первый тип генерации подключей, образующая функция F(Vi) = Vi", "1.png")
                                        graph(res2, "Первый тип генерации подключей, образующая функция F(Vi,X) = S(X) XOR Vi", "2.png")
                                        graph(res3, "Второй тип генерации подключей, образующая функция F(Vi) = Vi", "3.png")
                                        graph(res4, "Второй тип генерации подключей, образующая функция F(Vi,X) = S(X) XOR Vi", "4.png")
                                        
                                        sg.popup_ok("Графики сохранены в папку с программой")
                                        
                                        
                                        
                                        
                                        
                                            
                                        
                                        
                                        

main()