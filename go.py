import gdb

debug=True

class rt0_Amd64(gdb.Breakpoint):
    """
    在第二个函数上打断点，将 argc,argv输出出来
    """

    def __init__(self,addr,debug=False):
        print("{name}已经打上断点".format(name=addr))
        self._addr = addr
        self._debug = debug
        # 注册自己的断点
        super(self.__class__, self).__init__("{addr}".format(addr=addr),type=gdb.BP_BREAKPOINT)
        # Breakpoint.condition
    # 当停下来的时候
    def stop(self) -> bool:
        """
        TODO: 需要根据argc 获取全部的argv[]的指针，然后分别打印地址
        """
        frame = gdb.selected_frame()

        if self._debug: print("初始化的amdframe: ",frame)

        # 读取 rsi的值然后 x /a $rsi
        argc = int(frame.read_register("di"))
        print('argc: ', argc)
        argvA = ['' for i in range(argc)]
        for i in range(0,argc):
            argvPtr = gdb.parse_and_eval("$sp + %d"%((i + 1)*8)).const_value()
            # 这是 sp + 8的指针数组的首地址
            if self._debug: print("得到指针数组的第%d地址"%(i+1), argvPtr.const_value())
            
            ex = "x /a %s"%argvPtr
            tmp = gdb.execute(ex,True,True) #得到 指针数组的第一个指针
            tmp = tmp[tmp.find(':') + 1:].strip() # 格式为 地址： 值
            if self._debug:  print("指针数组的第一个指针:" ,tmp)
            ex= "x /s {}".format(tmp) #打印出这个 str
            argv = gdb.execute(ex,True,True)
            argvA[i] =  argv.split(':')[1].strip()[1:-2] # 去除 ""
        print("argv: ",argvA)
        return True 


class runtimeG:
    def __init__(self,addr,debug=False,print=True):
        self.debug = debug
        if self.debug: print("初始化runtime.g地址{addr}".format(addr=addr))
        self.addr = addr
        self.print = print
    def get_stack(self) -> list[str]:
        # 格式 addr: lo hi\n
        stack = gdb.execute('x /2a {addr}'.format(addr=self.addr), True,True).split('\n')[0].split('\t')[1:]
        if self.debug:print("stack: ", stack)
        if self.print: print('lo: {stack[0]}\thi: {stack[1]}'.format(stack=stack))
        return stack
    def get_stackguard(self)->list[str]:
        if self.debug: print("get_stackguard")
        stack = gdb.execute('x /2a ({addr} + 16)'.format(addr=self.addr), True,True).split('\n')[0].split('\t')[1:]
        # if self.debug:print("stackgurad : ", stack)
        if self.print: print('stackguard0: {stack[0]}\tstackgurad1: {stack[1]}'.format(stack=stack))
        return stack
    def get_stack_size(self)->int:
        stack= self.get_stack()
        print("get stack", stack)
        lo, hi = int(stack[0],16),int(stack[1],16)
        return hex(hi - lo)
    def getm0(self):
        m0 = gdb.execute('x /a ({addr} + 0x30 )'.format(addr=self.addr), True,True)
        return handlerOneLine(m0)
        
 
class runtimeM:
    def __init__(self,addr):
        print("初始化runtime.m地址: {addr}".format(addr=addr))
        self.addr = addr
    def get_tls(self):
        tmp = gdb.execute('x /2a ({addr} + 136)'.format(addr=self.addr), True,True)
        tmp = tmp.split('\n')
        for i in range(len(tmp)):
            if tmp[i] == '':
                tmp = tmp[:i].__iadd__(tmp[i+1:])
        # print('tmp' , tmp)
        tls = ['1' for i in range(len(tmp) * 2)]
        idx = 0
        for i in range(len(tmp)):
            t = tmp[i].split('\t')
            tls[idx], tls[idx+ 1] = t[1], t[2]
            idx += 2
        return tls
    def getg0(self):
        g0 = gdb.execute('x /a ({addr} )'.format(addr=self.addr), True,True)
        return handlerOneLine(g0)
    

   



def handlerOneLine(s):
    return s.split('\n')[0].split('\t')[1]

def get_entry_point():
    files = gdb.execute("info files",True,True).split('\n')
    entryPoint = ""
    for s in files:
        if "Entry point" in s:
            entryPoint = s[s.find("0x"):]
            return entryPoint
    return ""
entryPoint= get_entry_point()
gdb.execute("b *{}".format(entryPoint))
def ExtraceSymbolAddr(name):
    addr = gdb.execute("info address {}".format(name),True,True)
    return "{}".format(addr[addr.find('0x'):-2])  # 提取出来它的addr
    
rt0Amd64Addr = "*{}+4".format(ExtraceSymbolAddr("_rt0_amd64"))  # 提取出来它的addr
#TODO:debug去掉
rt0_Amd64(rt0Amd64Addr,debug=debug)
gdb.execute("run")
gdb.execute("c")


class runtimeRt0Go(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.m0 = self.getm0()
        self.g0 = self.getg0()
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.rt0_go")
        self.base = base
        runtimeRt0GoAddr= "*{}+54".format(base)  # 提取出来它的addr
        super(self.__class__, self).__init__("{addr}".format(addr=runtimeRt0GoAddr),type=gdb.BP_BREAKPOINT)
        if self.debug: print("runtime.rt0_go赋值的地方： 已经打上断点")
        checkMtlsAddr = "*{}+218".format(base)  # 提取出来它的addr
        super(self.__class__, self).__init__("{addr}".format(addr=checkMtlsAddr),type=gdb.BP_BREAKPOINT)
        print("检查 runtime.m 的tls是否正常工作： 已经打上断点")

        bingmg = "*{}+255".format(base)  # mg 相互绑定
        super(self.__class__, self).__init__("{addr}".format(addr=bingmg),type=gdb.BP_BREAKPOINT)
        print("m0 g0相互绑定： 已经打上断点")
        # Breakpoint.condition
    def getm0(self):
        return runtimeM(ExtraceSymbolAddr('runtime.m0'))
    def getg0(self):
        return runtimeG(ExtraceSymbolAddr('runtime.g0'))
            
    def handlerStack(self):
        # 将结构体打印g0，我们发现现在有3个值被赋予
        # 读取 stack
        print(self.g0.get_stack())
        print(self.g0.get_stackguard())
        print("分配了折磨多的栈空间: ", self.g0.get_stack_size())

    """
    检查 runtime.m 的tls是否正常工作 m.tls[0] = 0x123
    """
    def chekcMTLS(self):
        print("m0.tls[0] = ", self.m0.get_tls()[0])
    # m0 g0相互绑定
    def mgbind(self):
        g0 = self.m0.getg0()
        m0 = self.g0.getm0()
        print('m0 g0相互绑定', "m0.g0 ",g0, 'g0.m0', m0)

    # 当停下来的时候
    def stop(self) -> bool:
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16) 
        if pcdiff == 54:
            self.handlerStack()
        elif pcdiff == 218:
            self.chekcMTLS()
        elif pcdiff == 255:
            self.mgbind()
        return True
# class ()
    


runtimeRt0Go(debug=debug)

gdb.execute("c 4")
# 打印 argc