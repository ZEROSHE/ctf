L = []
for seg in Segments():
    if idc.SegName(seg)=='.text':
        ea = idc.SegStart(seg)
        eaend = idc.SegEnd(seg)
        index = 0
        while(ea < eaend):
            ea=idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN, '0xE8 0x02 0x00 0x00 0x00', radix=16)
            if ea!=idc.BADADDR:
                index = index + 1
                L.append(ea)
for seg in Segments():
    if idc.SegName(seg)=='.text':
        ea = idc.SegStart(seg)
        eaend = idc.SegEnd(seg)
        index = 0
        while(ea < eaend):
            ea=idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN, '0xE8 0x01 0x00 0x00 0x00', radix=16)
            if ea!=idc.BADADDR:
                index = index + 1
                L.append(ea)          
              
# for ea in L:
   # print('%s %x' %(idc.GetMnem(ea), ea))

count = 0               
eabegin = 0
eaover = 0
for ea in L:
    print('%x' %ea)
    getvoeraddr = 0
    enstart = ea
    eaend = ea + 50
    #GetEnd
    while(enstart < eaend):
        if(idc.Byte(enstart) == 0x74):
            eathen2 = enstart+2
            if(idc.Byte(eathen2) == 0xC2):
                eaover = enstart + 2 + 3 + 4
                getvoeraddr = 1
                print('GetStart1 0x%x' %(eaover))
                break
                
        enstart = enstart + 1
        
    if getvoeraddr == 0:
        enstart = ea
        eaend = ea + 50
        #GetEnd2
        while(enstart < eaend):
            if(idc.Byte(enstart) == 0x87):
                eathen = enstart+3
                eathen2 = enstart+2
                if(idc.Byte(eathen) == 0xC2):
                    eathen3 = enstart - 2
                    if (idc.Byte(eathen3) == 0x74 or idc.Byte(eathen3) == 0x75):
                        eaover = enstart + 3 + 3 + 4
                        print('GetStart2 0x%x' %(eaover))
                    else:
                        eaover = enstart + 3 + 3 + 2
                        print('GetStart3 0x%x' %(eaover))
                    break
            enstart = enstart + 1
        
    if enstart == eaend:
        continue
        
        
    enstart_00 = ea - 100
    enstart_0 = ea
    check = 0
    gnull = 0
    while(enstart_0>enstart_00):
        if idc.Word(enstart_0)==0x74ff or idc.Byte(enstart_0)==0x68 or idc.Byte(enstart_0)==0x50 or idc.Byte(enstart_0)==0x51 or idc.Word(enstart_0)==0xec83 or idc.Byte(enstart_0)==0x57 or idc.Byte(enstart_0)==0x53 or idc.Byte(enstart_0)==0x56:
            check = 0
            eabegin = enstart_0
        enstart_0 = enstart_0 - 1
        check = check + 1
        if check > 6:
            break
    if enstart_0 == enstart_00:
        continue
    count += 1
    print('start %x end %x %d' %(eabegin, eaover, count))
    
    
    patchstart = eabegin
    patchend = eaover
    while (patchstart < patchend):
        idc.PatchByte(patchstart, 0x90)
        patchstart += 1