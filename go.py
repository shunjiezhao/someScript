import gdb

debug=False
tp =False

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
        return tp


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
        print('stackguard0: {stack[0]}\tstackgurad1: {stack[1]}'.format(stack=stack))
        return stack
    def get_stack_size(self)->int:
        stack= self.get_stack()
        print("get stack", stack)
        lo, hi = int(stack[0],16),int(stack[1],16)
        return hex(hi - lo)
    def getm0(self):
        m0 = gdb.execute('x /a ({addr} + 0x30 )'.format(addr=self.addr), True,True)
        return handlerOneLine(m0)
    def get_gobuf(self):
#         0x38 sp,pc,g,cctx,ret,lr,bp
        addr2 = {
            "sp": '0x38',
            "pc": '0x40',
            "g": '0x48',
            "ctxt": '0x50',
            "ret": '0x58',
            "lt": '0x60',
            "bp": '0x68',
        }
        baseP = 'x /a %s + '%self.addr
        for k,v in addr2.items():
            ans = self.handler(v)
            addr2[k] =ans
        return addr2
    def handler(self,v):
        baseP = 'x /a %s + '%self.addr
        ans = handlerOneLine(gdb.execute(baseP + v,True,True))
        return ans

    def get_gopc(self):
        ans = self.handler('0x118')
        return ans
    def startpc(self):
        ans = self.handler('0x128')
        return ans









        
 
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
gdb.execute("layout split")
gdb.execute("run")


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
        # if self.debug: print("runtime.rt0_go赋值的地方： 已经打上断点")
        checkMtlsAddr = "*{}+218".format(base)  # 提取出来它的addr
        super(self.__class__, self).__init__("{addr}".format(addr=checkMtlsAddr),type=gdb.BP_BREAKPOINT)
        # print("检查 runtime.m 的tls是否正常工作： 已经打上断点")

        bingmg = "*{}+255".format(base)  # mg 相互绑定
        super(self.__class__, self).__init__("{addr}".format(addr=bingmg),type=gdb.BP_BREAKPOINT)
        # print("m0 g0相互绑定： 已经打上断点")
        # 将 runtime.main 放入 ax
        callNew = "*{}+303".format(base)  # 调用 newproc
        super(self.__class__, self).__init__("{addr}".format(addr=callNew),type=gdb.BP_BREAKPOINT)
        # print("m0 g0相互绑定： 已经打上断点")
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
    def newproc(self):
        str = """
        +---------------------+   
        |   runtime.mainpc    |      
        +---------------------+   
        |      arg size       |     ->  runtime.newproc
        +---------------------+ 
        """
        print(str)

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
        elif pcdiff == 303:
            self.newproc()
        return tp



runtimeRt0Go(debug=debug)

class Osinit(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.addr = ExtraceSymbolAddr("runtime.osinit")
        Ncpu = self.addr + "+37"
        super(self.__class__, self).__init__("*{addr}".format(addr=Ncpu),type=gdb.BP_BREAKPOINT)
        hugePageAddr= self.addr + "+59"
        super(self.__class__, self).__init__("*{addr}".format(addr=hugePageAddr),type=gdb.BP_BREAKPOINT)

    def stop(self) ->bool:
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.addr, 16) 
        if pcdiff == 37:
            self.ncpu = gdb.parse_and_eval("$rax")
            return False
        else:
            self.hugePageSize = hex(gdb.parse_and_eval("$rax"))
        print("ncpu: ", self.ncpu, "hugePageSize: ", self.hugePageSize)
        return tp

def cmpStr(a:gdb.Value,b:str)->bool:
    return a.__str__().strip() == b
Osinit()
class Schedinit(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.addr = ExtraceSymbolAddr("runtime.schedinit")
        getG0= self.addr + "+32"
        super(self.__class__, self).__init__("*{addr}".format(addr=getG0),type=gdb.BP_BREAKPOINT,temporary=True)
        setMcount= self.addr + "+47"
        super(self.__class__, self).__init__("*{addr}".format(addr=setMcount),type=gdb.BP_BREAKPOINT,temporary=True)
        super(self.__class__, self).__init__("runtime.procresize",type=gdb.BP_BREAKPOINT)
        self.ProcAddr = ExtraceSymbolAddr("runtime.procresize")
        growAllp = self.ProcAddr + "+1323"
        super(self.__class__, self).__init__("*{addr}".format(addr=growAllp),type=gdb.BP_BREAKPOINT,temporary=True)
        addr = self.ProcAddr + "+349"
        super(self.__class__, self).__init__("*{addr}".format(addr=addr),type=gdb.BP_BREAKPOINT,temporary=True)
        addr = self.ProcAddr + "+514" # m.p = p0
        super(self.__class__, self).__init__("*{addr}".format(addr=addr),type=gdb.BP_BREAKPOINT,temporary=True)
        addr = self.ProcAddr + "+814" # m.p = p0
        super(self.__class__, self).__init__("*{addr}".format(addr=addr),type=gdb.BP_BREAKPOINT,temporary=True)
    def stop(self) ->bool:
        frame = gdb.selected_frame()
        # runtime.schedinit()
        pcdiff = frame.pc() - int(self.addr, 16)
        if pcdiff == 32:
            g0Addr = gdb.parse_and_eval("$rax")
            # ex = "x /a %s"%g0Addr
            tmp = gdb.execute("x /a %s"%g0Addr,True,True) #得到g的地址
            print(tmp[:tmp.find(':')])
            self.g0 = runtimeG(g0Addr)
        elif pcdiff == 47:
            print("set M max count 10000")

        print(frame.function())

        if cmpStr(frame.function(), "runtime.procresize"):
            pcdiff = frame.pc() - int(self.ProcAddr, 16)
            if  pcdiff == 1323:
                print("扩容 allp 数组 [1,2,3] -> [1,2,3,nil,nil,nil]")
            elif pcdiff == 349:
                print("将allp 中所有的 P 进行初始化")
            elif pcdiff == 514:
                print("将 runtime.acquirep() -> wirep(p):将当前的getg().m.p 设置为p 并更改 p 的状态 ;其实就是 m.p = allp[0] ")
            elif pcdiff == 814:
                print("在这之前我们将多余的 P 销毁了")
                print("\t初始化的时候 所有的 P 的G队列都是空，并且他们是刚初始化的时候，所以状态为IDLE(0)，然后将所有的P放入空闲P列表中，因为是从后往前遍历的所以我们会返回 allp[0]")
            else:
                print("开始初始化 P 根据我们的 ncpu 个数和 传入的 nprocs取最小值,这里会将所有 P 一次性分配完成")
            return True

        return True
Schedinit()

class systemStack(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        base = ExtraceSymbolAddr("runtime.systemstack")
        self.base = base
        self.g0 = ExtraceSymbolAddr("runtime.g0")
        base += '+27'
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        base += '+100'
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
    def getm0(self):
        return runtimeM(ExtraceSymbolAddr('runtime.m0'))
    def getg0(self):
        return runtimeG(ExtraceSymbolAddr('runtime.g0'))
    def stop(self) ->bool:
        print("如果是g0的话，就不需要切换地址栈")
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16)
        # m bx ; dx =g0; ax = g
        g = gdb.parse_and_eval("$rax")
        if g == self.g0:
            print("当前的g是g0不用切换栈")
            return False
        if pcdiff == 100:
            print("当前的栈不是需要切换")
            curg = runtimeG(g)
            print('保存的信息:\n\t',curg.get_gobuf())
        return True

class runtimePPrinter:
    def __init__(self,val) -> None:
        self.val = val
    # 必选，打印输出结果
    def to_string(self):
        return "m: {} runq: {} runnext: {} ".format(hex(self.val['m']), self.val['runq'],hex(self.val['runnext']))

    def display_hint(self):
        return 'map'
def lookup_buffer(val):
    """val是一个gdb.Value的实例，通过type属性来获取它的类型。
    如果类型为Buffer，那么就使用自定义的BufferPrinter。
    """
    if str(val.type) == 'runtime.p':
        return runtimePPrinter(val)
    print(str(val.type))
    return None
def build_pretty_printer():
    pp = gdb.printing.RegexpCollectionPrettyPrinter(
        "my_library")
    pp.add_printer('runtime.p', '^runtime.p$', runtimePPrinter)
    return pp

gdb.printing.register_pretty_printer(gdb.current_objfile(), build_pretty_printer())





class runtimeNewProc(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.m0 = self.getm0()
        self.g0 = self.getg0()
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.newproc")
        self.base = base
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        # callNew = "*{}+303".format(base)  # 调用 newproc
        # print("m0 g0相互绑定： 已经打上断点")
        base = ExtraceSymbolAddr("runtime.newproc1") # newproc1
        self.proc1Addr = base
        super(self.__class__, self).__init__("*{addr} + 125".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True) #从 free list 得到空闲g
        super(self.__class__, self).__init__("*{addr} + 408".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True) # 设置 g 的一些信息
        super(self.__class__, self).__init__("*{addr} + 640".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True) # 将 g 放入 p 的队列里面
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
            systemStack()
        if cmpStr(frame.function().__str__(), "runtime.newproc1"):
            pcdiff = frame.pc() - int(self.proc1Addr, 16)
            if pcdiff == 125:
                print("从 free list 得到的 G 为空，我们制造一个 G 然后加入全局的G中")
            elif pcdiff == 408:
                newg = runtimeG(hex(gdb.parse_and_eval('$rcx')))
                print('newg.sched: ',newg.get_gobuf())
                print('newg.gopc(也就是我们调用者的pc值): ' ,newg.get_gopc())
                print('newg.startpc: ' ,newg.startpc())
            elif pcdiff == 640:
                print("将 newg 放入 p 的 g 队列里面，当最后一个参数是 true 的时候 p.next")
                print( gdb.parse_and_eval("*_p_"),'newg:', gdb.parse_and_eval('newg'))

        return True
# class ()
runtimeNewProc()

# mstart
class mstart1(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.init = True
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.mstart1")
        self.base = base
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
    def stop(self) -> bool:
        if self.init:
            print("""
                mstart1 主要做了这样的事情
                保存 pc,sp 至 当前 g.sched
                记录calLer，用作mcall中的堆顶和终止线程
                我们再也不回mstart1了
                所以其他调用可以重用当前帧
            """)
            self.init = True
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16)
        if pcdiff == 84:
            _g_ = runtimeG(gdb.parse_and_eval('_g_'))
            print("保存 信息至 当前 G.sched")
            print(_g_.get_gobuf())
        return True
mstart1()
class schedule(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.init = True
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.schedule")
        self.base = base
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
    def stop(self) -> bool:
        if self.init:
            print("""
            schedule() 主要做的事情是：
                1. 如果当前GC需要停止整个世界（STW), 则调用gcstopm休眠当前的M。
                2. 每隔61次调度轮回从全局队列找，避免全局队列中的g被饿死。
                3. 从p.runnext获取g，从p的本地队列中获取。
                4. 调用 findrunnable (local global netpoll steal )找g，找不到的话就将m休眠，等待唤醒。
                5. 找到了g，那就执行g上的任务函数(也就是 go.startpc)
            """)
            self.init = False
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16)

        return True
schedule()
class execute(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.init = True
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.execute")
        self.base = base
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
    def stop(self) -> bool:
        if self.init:
            print("""
            execute() 主要做的事情是：
            1. 双向绑定 准备运行的 G 和 M 如果是初始化就是 g0, m0
            2. gogo的作用
                1. 把gp.sched的成员恢复到CPU的寄存器完成状态以及栈的切换；
                2. 跳转到gp.sched.pc所指的指令地址（初始化时也就是：runtime.main）处执行
            """)
            self.init = False
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16)
        return True
execute()

class gogo(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.init = True
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.gogo")
        self.base = base
        super(self.__class__, self).__init__("*{addr}+35".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        super(self.__class__, self).__init__("*{addr}+85".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        self.tmp ={}
    def stop(self) -> bool:
        if self.init:
            print("""
            gogo(*gobuf) 传入的是准备 run 的 G
            0. 要运行的g的指针放入线程本地存储，这样后面的代码就可以通过线程本地存储 获取到当前正在执行的goroutine的g结构体对象，从而找到与之关联的m和p
            1. 把gp.sched的成员恢复到CPU的寄存器完成状态以及栈的切换；
            2. 跳转到gp.sched.pc所指的指令地址（初始化时也就是：runtime.main）处执行
            """)
            self.init = False
        # 首先得到我们的G
        frame = gdb.selected_frame()
        pcdiff = frame.pc() - int(self.base, 16)
        if pcdiff == 35:
            self.tmp["sp"] = frame.read_register('rsp')
            self.tmp["bp"] = frame.read_register('rbp')
            return False
        else:
            print("SP: ", self.tmp["sp"] , '->',frame.read_register('rsp'))
            self.tmp["sp"] = frame.read_register('rsp')
            print("BP: ", self.tmp["bp"] , '->',frame.read_register('rbp'))
            print("PC: ", gdb.execute("x /i $rbx",True,True).split(':')[0])
        return True
gogo()
class runtimeMain(gdb.Breakpoint):
    def __init__(self,debug=False):
        self.debug = debug
        self.init = True
        # 注册自己的断点
        base = ExtraceSymbolAddr("runtime.main")
        self.base = base
        super(self.__class__, self).__init__("*{addr}".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        # super(self.__class__, self).__init__("*{addr}+85".format(addr=base),type=gdb.BP_BREAKPOINT,temporary=True)
        self.tmp ={}
    def stop(self) -> bool:
        if self.init:
            print("""
            runtime.main 
                1. 启动一个sysmon系统监控线程，该线程负责整个程序的gc、抢占调度以及netpoll等功能的监控
                2. 执行runtime包的初始化；
                3. 执行main包以及main包import的所有包的初始化；
                4. 执行main.main函数；
                5. 从main.main函数返回后调用exit系统调用退出进程；（也就是我们的函数哈哈哈，结束了）
            """)
            self.init = False
        # 首先得到我们的G
        return True
runtimeMain()