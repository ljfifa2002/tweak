#import "RestoreSymbol.h"
#import <objc/runtime.h>
#import <dlfcn.h>

@implementation RestoreSymbol

-(NSArray*)getAllClass:(NSString *)modulePath{

    if (!modulePath) {
        
        NSBundle *bundle = [NSBundle mainBundle];
        modulePath = [bundle executablePath];
    }
    
    unsigned int classCount;
    const char** pClasses = objc_copyClassNamesForImage(modulePath.UTF8String, &classCount);
    
    NSMutableArray *arrayClassName = [[NSMutableArray alloc] init];
    for (int i=0; i<classCount; i++) {
        
        const char *pClassName = pClasses[i];
        if (!pClassName) {
            continue;
        }
        NSString *className = [NSString stringWithCString:pClassName encoding:NSUTF8StringEncoding];
        //NSLog(@"className %@", className);
        [arrayClassName addObject:className];
    }
    
    free(pClasses);
    
    return arrayClassName;
}

-(NSArray*)getAllMethods:(NSString*)className{
    
    Class objClass = objc_getClass(className.UTF8String);
    Class metaClass = objc_getMetaClass(className.UTF8String);
    
    u_int count;
    Method *methods = class_copyMethodList(objClass, &count);
    
    NSMutableArray *arrayMethodName = [[NSMutableArray alloc] init];
    for (int i =0; i<count; i++)
    {
        SEL name = method_getName(methods[i]);
        const char *selName= sel_getName(name);
        IMP imp = method_getImplementation(methods[i]);
        
        if (!selName) {
            continue;
        }
        NSString *strName = [NSString stringWithCString:selName encoding:NSUTF8StringEncoding];
        NSString *strImp = [NSString stringWithFormat:@"%ld", imp];
        
        //NSLog(@"%@",strName);
        NSDictionary *dic = [NSDictionary dictionaryWithObjectsAndKeys:
                             strName,@"name",
                             strImp,@"imp",
                             @"-", @"type",
                             nil];
        
        [arrayMethodName addObject:dic];
    }
    
    Method *metaMethods = class_copyMethodList(metaClass, &count);
    for (int i =0; i<count; i++)
    {
        SEL name = method_getName(metaMethods[i]);
        const char *selName= sel_getName(name);
        IMP imp = method_getImplementation(metaMethods[i]);
        
        if (!selName) {
            continue;
        }
        NSString *strName = [NSString stringWithCString:selName encoding:NSUTF8StringEncoding];
        NSString *strImp = [NSString stringWithFormat:@"%ld", imp];
        
        NSDictionary *dic = [NSDictionary dictionaryWithObjectsAndKeys:
                             strName,@"name",
                             strImp,@"imp",
                             @"+", @"type",
                             nil];
        
        [arrayMethodName addObject:dic];
    }
    
    free(methods);
    free(metaMethods);
    //NSLog(@"%u",count); // 171个方法;包括很多私有方法;
    return arrayMethodName;
}
    
-(NSString*)findSymbol:(NSString*)modulePath :(long)addr{
    
    NSString *className, *methodName, *methodType;
    NSArray *arrayClassName = [self getAllClass:modulePath];
    long tmpDis, theDis = 3000000000;
    
    for (int i=0; i<arrayClassName.count; i++) {
        
        NSString *findClassName = [arrayClassName objectAtIndex:i];
        NSArray *arrayMethod = [self getAllMethods:findClassName];
        //NSLog(@"arrayMethod: %@", arrayMethod);
        
        
        for (int j=0; j<arrayMethod.count; j++) {
            
            if ([[arrayMethod objectAtIndex:j][@"name"] isEqualToString:@"loadViewIfRequired"]) {
                //NSLog(@"loadViewIfRequired");
            }
            NSString *methodImp = [arrayMethod objectAtIndex:j][@"imp"];
            if (addr >= [methodImp longLongValue]) {  //地址肯定大于方法名称
                
                tmpDis = addr - [methodImp longLongValue];
                if (tmpDis < theDis) {
                
                    theDis = tmpDis;
                    className = [arrayClassName objectAtIndex:i];
                    methodName = [arrayMethod objectAtIndex:j][@"name"];
                    methodType = [arrayMethod objectAtIndex:j][@"type"];
                }
            }
        }
        
    }
    
    NSString *symbolName = [NSString stringWithFormat:@"%@ [%@ %@]", methodType, className, methodName];
    return symbolName;
    
}

-(NSDictionary*)getModuleInfo:(long)addr{
    
    int ret;
    Dl_info dylib_info;
    if ((ret = dladdr(addr, &dylib_info))) {
       
        const char *fname = dylib_info.dli_fname;
        void *fbase = dylib_info.dli_fbase;
        const char *sname = dylib_info.dli_sname;
        void *saddr = dylib_info.dli_saddr;
        
        if ((!fname) || (!fbase) || (!sname) || (!saddr)) {
            return nil;
        }
        NSString *strFname = [NSString stringWithCString:fname encoding:NSUTF8StringEncoding];
        NSString *strFbase = [NSString stringWithCString:fbase encoding:NSUTF8StringEncoding];
        NSString *strSname = [NSString stringWithCString:sname encoding:NSUTF8StringEncoding];
        NSString *strFaddr = [NSString stringWithCString:saddr encoding:NSUTF8StringEncoding];
        
        NSDictionary *dic = [NSDictionary dictionaryWithObjectsAndKeys:
                             strFname, @"fname",
                             strFbase, @"fbase",
                             strSname, @"sname",
                             strFaddr, @"saddr",
                             nil];
        return dic;
       
    }
    
    return nil;
    
}

-(NSMutableString*)findSymbolFromAddress:(NSString*)module_path :(long)frame_addr{

    if (module_path == nil) {
        module_path = [[NSBundle mainBundle] executablePath];
    }
    const char *path = module_path.UTF8String;
    
    // NSMutableDictionary *retdict = [NSMutableDictionary dictionary];
    // NSMutableArray *retArr = [NSMutableArray array];
    unsigned int c_size = 0;
    const char **allClasses = (const char **)objc_copyClassNamesForImage(path, &c_size);
    
    NSString *c_size_str = [@(c_size) stringValue];
    uintptr_t tmpDis = 0;
    uintptr_t theDistance = 0xffffffffffffffff;
    uintptr_t theIMP = 0;
    NSString* theMethodName = nil;
    NSString* theClassName = nil;
    NSString* theMetholdType = nil;
    // go all class
    for (int i = 0; i < c_size; i++) {
        Class cls = objc_getClass(allClasses[i]);
        tmpDis = 0;
        // for methold of a class
        unsigned int m_size = 0;
        struct objc_method ** metholds = (struct objc_method **)class_copyMethodList(cls, &m_size);
        // NSMutableDictionary *tmpdict = [NSMutableDictionary dictionary];
        for (int j = 0; j < m_size; j++) {
            struct objc_method * meth = metholds[j];
            IMP implementation = method_getImplementation(meth);
            NSString* m_name = NSStringFromSelector((SEL)method_getName(meth));
            // [tmpdict setObject:m_name forKey:(id)[@((uintptr_t)implementation) stringValue]];
            
            if ([m_name isEqualToString:@"loadViewIfRequired"]) {
                          // NSLog(@"loadViewIfRequired");
                       }
            
            if(frame_addr >= (uintptr_t)implementation){
                if((frame_addr - (uintptr_t)implementation) <= theDistance){
                    theDistance = frame_addr - (uintptr_t)implementation;
                    theIMP = (uintptr_t)implementation;
                    theMethodName = m_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                    theMetholdType = @"-";
                }
            }
        }
        
        // for class methold of a class
        unsigned int cm_size = 0;
        struct objc_method **classMethods = (struct objc_method **)class_copyMethodList((Class)objc_getMetaClass((const char *)class_getName(cls)), &cm_size);
        for (int k = 0; k < cm_size; k++) {
            struct objc_method * meth = classMethods[k];
            IMP implementation = method_getImplementation(meth);
            NSString* cm_name = NSStringFromSelector((SEL)method_getName(meth));
            // [tmpdict setObject:cm_name forKey:(id)[@((uintptr_t)implementation) stringValue]];
            if(frame_addr >= (uintptr_t)implementation){
                if((frame_addr - (uintptr_t)implementation) <= theDistance){
                    theDistance = frame_addr - (uintptr_t)implementation;
                    theIMP = (uintptr_t)implementation;
                    theMethodName = cm_name;
                    theClassName = (NSString*)NSStringFromClass(cls);
                    theMetholdType = @"+";
                }
            }
        }
        free(metholds);
        free(classMethods);
        // [retdict setObject:tmpdict forKey:(NSString*)NSStringFromClass(cls)];
    }
    
    free(allClasses);
    NSMutableString* retStr = [NSMutableString string];
    
    if ((!theDistance) || (!theMetholdType) || (!theClassName) || (!theMethodName)) {
        return @"null";
    }
    
    NSString *moduleName = [module_path lastPathComponent];
    [retStr appendString:moduleName];
    [retStr appendString:@"`"];
    [retStr appendString:theMetholdType];
    [retStr appendString:@"["];
    [retStr appendString:theClassName];
    [retStr appendString:@" "];
    [retStr appendString:theMethodName];
    [retStr appendString:@"]"];
    // [retStr appendString:@" -> "];
    // [retStr appendString:(id)[@((uintptr_t)theIMP) stringValue]];
    [retStr appendString:@" + "];
    [retStr appendString:(id)[@((uintptr_t)theDistance) stringValue]];

    return retStr;
}

-(NSMutableArray*)outputCallStackSymbol{
    
    NSArray *stackSymbols = [NSThread callStackSymbols];
    
    NSMutableArray *newStackSymbols = [[NSMutableArray alloc] init];
    
    for (int i=0; i<stackSymbols.count; i++) {

        //2   Foundation                          0x0000000191d733f0 C82F8A4F-3D0F-33DB-8D40-C1E8BEF27E56 + 1127408
        
        NSString *symbolInfo = [stackSymbols objectAtIndex:i];
        
        NSString *frameNum, *moduleName, *symbolAddr, *symbolName;
        frameNum = [symbolInfo substringToIndex:1];
        //NSLog(@"frameNum: %@", frameNum);
        
        
        NSArray * arr = [symbolInfo componentsSeparatedByString:@" "];
        //NSLog(@"arr %@", arr);
        
        int matchNum = 0;
        for (int i=0; i<arr.count; i++) {
            
            if (i==0) {
                frameNum = [arr objectAtIndex:i];
                matchNum = 1;
            }
            
            NSString *str = [arr objectAtIndex:i];
            if (![str isEqualToString:@""]) {
                
                if (matchNum == 2) {
                    moduleName = str;
                    
                }
                else if(matchNum == 3){
                    symbolAddr =str;
                }
                else if(matchNum == 4){
                    symbolName =str;
                    break;
                }
                matchNum++;
            }
        }
        
        /*
        NSLog(@"frameNum: %@", frameNum);
        NSLog(@"moduleName: %@", moduleName);
        NSLog(@"symbolAddr: %@", symbolAddr);
        NSLog(@"symbolName: %@", symbolName);
        */
        
        long addr = strtoul([symbolAddr UTF8String],0,16);
        //NSLog(@"转换完的数字为：%lx",addr);
            
        NSDictionary *moduleDic = [self getModuleInfo:addr];
        NSString *modulePath = moduleDic[@"fname"];
        //NSLog(@"modulePath: %@", modulePath);
        
        if ([modulePath containsString:@"appMonitor.dylib"]) {
            continue;
        }
        else if([modulePath hasPrefix:@"/System/Library"]){
            continue;
        }
        
        
        //NSString *newSymbolName = [self findSymbol:moduleDic[@"fname"] :addr];
        //NSLog(@"newSymbolName :%@", newSymbolName);
    
        NSString *newSymbolName2 = [self findSymbolFromAddress:modulePath :addr];
        //NSLog(@"newSymbolName2 %@", newSymbolName2);
        
        /*
        else if([newSymbolName2 containsString:@"/System/Library/Frameworks/Foundation.framework/UIKit"]){
            
        }
         */
        
        [newStackSymbols addObject:newSymbolName2];
    }
    
     return newStackSymbols;
}
    
@end
