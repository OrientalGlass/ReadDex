// Created by OrientalGlass on 2024/12/19.
#include "DexFile.h"
#include "Leb128.h"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <process.h>
#include <string>
#include <vector>
#include <format>
// Tool functions
// 以二进制形式读取整个文件，返回字节数组并返回文件长度
unsigned char* readFileToBytes(const std::string& filePath, size_t& fileLength) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cout<<"Open file failed!"<<std::endl;
        return nullptr;  // 文件打开失败，返回空指针
    }
    // 获取文件大小
    file.seekg(0, std::ios::end);
    fileLength = file.tellg();
    file.seekg(0, std::ios::beg);
    if(fileLength==0) {
        std::cout<<"File is empty!"<<std::endl;
        return nullptr;
    }
    // 动态分配字节数组内存，大小为文件长度
    try {
        //申请4K对齐的空间
        unsigned char* buffer = new(std::align_val_t{0x1000}) unsigned char[fileLength];
        // 读取文件内容到buffer并返回
        if (file.read((char*)buffer, fileLength))
            return buffer;
        std::cout<<"Read file failed!"<<std::endl;
        delete[] buffer;//读取失败
        return nullptr;
    }catch (std::bad_alloc& e) {
        std::cout<<"Memory allocation failed! "<<e.what()<<std::endl;
        return nullptr;
    }
}
// 以16进制打印字节流
void printHexBytes(unsigned char* bytes,size_t len) {
    if (bytes==nullptr||len==0) {
        std::cout<<"Empty buffer!"<<std::endl;
        return;
    }
    for (size_t i = 0; i < len-1; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("%02x", bytes[len-1]);
}
// 以字符型打印字节流
void printCharBytes(unsigned char* bytes,size_t len) {
    if (bytes==nullptr||len==0) {
        std::cout<<"Empty buffer!"<<std::endl;
        return;
    }
    for (size_t i = 0; i < len; i++) {
        printf("%c", bytes[i]);
    }
}
// 检查索引是否合法
bool checkIndexIsLegal(u4 index,u4 maxIndex) {
    if(index>maxIndex) {
        //printf("No such index: %#x!\n",index);
        return false;
    }
    return true;
}
// 处理不合法索引
void illegalIndex(u4 index) {
    printf("No such index: %x\n",index);
    exit(0);
}

// 根据输入的字符串解析对应类型 将形如"[Landroid/content/ContentProviderClient;"的字符串去除前缀L,[和后缀;并替换所有/为.
std::string DexFile::parseString(std::string input) {
    // 基本类型直接返回对应类型字符串即可
    static std::map<char, std::string> typeMapping = {
        {'V', "void"},
        {'Z', "boolean"},
        {'B', "byte"},
        {'S', "short"},
        {'C', "char"},
        {'I', "int"},
        {'J', "long"},
        {'F', "float"},
        {'D', "double"},
    };
    if(input.empty())
        return "";
    //1. 基本类型直接返回对应完整类型字符串
    if(input.length()==1)
        return typeMapping[input[0]];

    //2. 引用类型需要去除[前缀 或者去除 L前缀和;后缀 将/替换为.
    std::string result=input;
    //数组类型 去除[前缀 递归处理 支持解析多级数组
    if(input.front()=='[') {
        result=parseString(input.substr(1))+"[]";
    }
    //引用类型 去除L前缀和;后缀 直接去除即可
    if ( input.front() == 'L' && input.back() == ';') {
        result = input.substr(1, input.size() - 2);
        for (char & chr : result) {
            if (chr == '/')
                chr = '.';
        }
    }
    return result;
}

// Init functions
void DexFile::initFields(unsigned char* buffer) {
    if(buffer==nullptr) {
        printf("Null pointer provided!\n");
        exit(0);
    }
    baseAddr=buffer;
    pHeader=(DexHeader*)baseAddr;
    pStringIds=(DexStringId*)(baseAddr+pHeader->stringIdsOff);
    pTypeIds=(DexTypeId*)(baseAddr+pHeader->typeIdsOff);
    pFieldIds=(DexFieldId*)(baseAddr+pHeader->fieldIdsOff);
    pMethodIds=(DexMethodId*)(baseAddr+pHeader->methodIdsOff);
    pProtoIds=(DexProtoId*)(baseAddr+pHeader->protoIdsOff);
    pClassDefs=(DexClassDef*)(baseAddr+pHeader->classDefsOff);
}
DexFile::DexFile(unsigned char *buffer) {
    initFields(buffer);
}
DexFile::DexFile(std::string filePath) {
    size_t fileLength=0;
    initFields(readFileToBytes(filePath, fileLength));
}
DexFile::~DexFile() {
    delete baseAddr;
}

// StringId functions
// 通过索引获取对应StringId
DexStringId DexFile::getStringIdByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->stringIdsSize-1)) {
        return pStringIds[index];
    }
    illegalIndex(index);
}
// 解析StringId 获取字符串长度
size_t DexFile::getStringDataLength(DexStringId& stringId) {
    const u1* ptr = baseAddr + stringId.stringDataOff;
    size_t size=0;
    myReadUnsignedLeb128(ptr,&size);
    return size;
}
// 解析StringId 获取字符串
std::string DexFile::getStringIdData(const DexStringId& stringId) {
    const u1* ptr = baseAddr + stringId.stringDataOff;
    while (*(ptr++) > 0x7f);// Skip the uleb128 length.
    return (char*)ptr;
}
// 通过索引获取StringId的字符串
std::string DexFile::getStringIdDataByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->stringIdsSize-1)) {
        return getStringIdData(pStringIds[index]);
    }
    return "NULL String";
}

// TypeId functions
// 通过索引获取对应TypeId
DexTypeId DexFile::getTypeIdByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->typeIdsSize-1)) {
        return pTypeIds[index];
    }
    illegalIndex(index);
}
// 通过索引获取TypeId对应的字符串
std::string DexFile::getTypeIdDataByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->typeIdsSize-1)) {
        return getStringIdDataByIndex(pTypeIds[index].descriptorIdx);
    }
    return "NULL Type";
}

// ProtoId functions
const DexProtoId DexFile::getProtoIdByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->protoIdsSize-1)) {
        return pProtoIds[index];
    }
    illegalIndex(index);
}
// 获取ProtoId对应短方法签名 即返回值和参数列表的缩写类型
std::string DexFile::getProtoIdShorty(const DexProtoId& protoId) {
    return getStringIdDataByIndex(protoId.shortyIdx);
}
// 获取返回值类型
std::string DexFile::getProtoIdReturnType(const DexProtoId& protoId) {
    return getTypeIdDataByIndex(protoId.returnTypeIdx);
}
// 获取ProtoId的参数列表,解析TypeList结构
std::vector<std::string> DexFile::getProtoIdParameters(const DexProtoId& protoId) {
    std::vector<std::string> parameters;
    //无参数
    if(protoId.parametersOff==0) {
        return parameters;
    }
    //解析TypeList结构 获取参数列表
    DexTypeList* typeList=(DexTypeList*)(baseAddr+protoId.parametersOff);
    for(int i=0;i<typeList->size;i++) {
        parameters.push_back(getTypeIdDataByIndex(typeList->list[i].typeIdx));
    }
    return parameters;
}
// 解析DexProtoId结构体 返回解析后的字符串
std::string DexFile::parseProtoId(const DexProtoId& protoId) {
    std::string shorty=getProtoIdShorty(protoId);//c++的string类型会自动遍历const char*字符串并复制
    std::string return_type = getProtoIdReturnType(protoId);
    std::vector<std::string> parameters=getProtoIdParameters(protoId);

    std::string result;
    result+=parseString(return_type)+" (";
    //解析参数
    for(int i=0;i<parameters.size();i++) {
        result+=parseString(parameters[i]);
        if(i!=parameters.size()-1)//多个参数以,分隔
            result+=",";
    }
    result+=")";
    return result;
}
// 通过索引解析ProtoId,返回解析后的对应字符串
std::string DexFile::getProtoIdDataByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->protoIdsSize-1)) {
        return parseProtoId(getProtoIdByIndex(index));
    }
    return "NULL Proto";
}

// FieldId functions
const DexFieldId DexFile::getFieldIdByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->fieldIdsSize-1)) {
        return pFieldIds[index];
    }
    illegalIndex(index);
}
// 获取FieldId所在类类名
std::string DexFile::getFieldIdClass(const DexFieldId& fieldId) {
    return getTypeIdDataByIndex(fieldId.classIdx);
}
// 获取FieldId类型
std::string DexFile::getFieldIdType(const DexFieldId& fieldId) {
    return getTypeIdDataByIndex(fieldId.typeIdx);
}
// 获取FieldId名称
std::string DexFile::getFieldIdName(const DexFieldId& fieldId) {
    return getStringIdDataByIndex(fieldId.nameIdx);
}
// 解析DexFieldId结构,字段所在类,类型,名称
std::string DexFile::parseFieldId(const DexFieldId& fieldId) {
    std::string fieldClass=getFieldIdClass(fieldId);
    std::string fieldType=getFieldIdType(fieldId);
    std::string fieldName=getFieldIdName(fieldId);
    return parseString(fieldType)+" "+parseString(fieldClass)+"."+fieldName;
}
// 通过索引获取FieldId对应的字符串
std::string DexFile::getFieldIdDataByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->fieldIdsSize-1)) {
        return parseFieldId(getFieldIdByIndex(index));
    }
    return "NULL Field";
}

// MethodId functions
const DexMethodId DexFile::getMethodIdByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->methodIdsSize-1)) {
        return pMethodIds[index];
    }
    illegalIndex(index);
}
// 获取MethodId所在类名
std::string DexFile::getMethodIdClass(const DexMethodId& methodId) {
    return getTypeIdDataByIndex(methodId.classIdx);
}
// 获取MethodId对应方法签名
std::string DexFile::getMethodIdProto(const DexMethodId& methodId) {
    return getProtoIdDataByIndex(methodId.protoIdx);
}
// 获取MethodId对应方法名
std::string DexFile::getMethodIdName(const DexMethodId& methodId) {
    return getStringIdDataByIndex(methodId.nameIdx);
}
// 解析DexMethodId结构
std::string DexFile::parseMethodId(const DexMethodId& methodId) {
    std::string methodProto=getMethodIdProto(methodId);
    //解析class并拼接name
    std::string methodFullName=parseString(getMethodIdClass(methodId))+getMethodIdName(methodId);
    //拼接proto和class.name
    return methodProto.insert(methodProto.find(' ')+1,methodFullName);
}
// 通过索引获取MethodId对应字符串
std::string DexFile::getMethodIdDataByIndex(u4 index) {
    if(checkIndexIsLegal(index,pHeader->methodIdsSize-1)) {
        return parseMethodId(getMethodIdByIndex(index));
    }
    return "NULL Method";
}

//print functions
void DexFile::printDexHeader() {
    printf("DexHeader:\n");
    printf("\tmagic: ");printHexBytes(pHeader->magic,sizeof(pHeader->magic));printf("\n");
    printf("\tchecksum: %#x\n",pHeader->checksum);
    printf("\tsignature: ");printHexBytes(pHeader->signature,kSHA1DigestLen);printf("\n");
    printf("\tFileSize: %#x\n",pHeader->fileSize);
    printf("\tHeaderSize: %#x\n",pHeader->headerSize);
    printf("\tEndianTag: %#x\n",pHeader->endianTag);
    printf("\tLinkOff: %#x\n",pHeader->linkOff);
    printf("\tLinkSize: %#x\n",pHeader->linkSize);
    printf("\tMapOff: %#x\n",pHeader->mapOff);
    printf("\tStringIDs Offset: %#x\n",pHeader->stringIdsOff);
    printf("\tNum of StringIDs: %#x\n",pHeader->stringIdsSize);
    printf("\tTypeIDs Offset: %#x\n",pHeader->typeIdsOff);
    printf("\tNum of TypeIDs: %#x\n",pHeader->typeIdsSize);
    printf("\tProtoIDs Offset: %#x\n",pHeader->protoIdsOff);
    printf("\tNum of ProtoIDs: %#x\n",pHeader->protoIdsSize);
    printf("\tFieldIDs Offset: %#x\n",pHeader->fieldIdsOff);
    printf("\tNum of FieldIDs: %#x\n",pHeader->fieldIdsSize);
    printf("\tMethodIDs Offset: %#x\n",pHeader->methodIdsOff);
    printf("\tNum of MethodIDs: %#x\n",pHeader->methodIdsSize);
    printf("\tClassDefs Offset: %#x\n",pHeader->classDefsOff);
    printf("\tNum of ClassDefs: %#x\n",pHeader->classDefsSize);
    printf("\tData Offset: %#x\n",pHeader->dataOff);
    printf("\tSize of Data: %#x\n",pHeader->dataSize);
    printf("DexHeader End\n");
}
void DexFile::printStringIds() {
    printf("StringIds:\n");
    printf("\tNums\t\tStrings\n");
    for(int i=0;i<pHeader->stringIdsSize;i++) {
        printf("\t%08x\t%s\n",i,getStringIdDataByIndex(i).c_str());
    }
    printf("StringIds End\n");
}
void DexFile::printTypeIds() {
    printf("TypeIds:\n");
    printf("\tNums\t\tTypeIds\n");
    for(int i=0;i<pHeader->typeIdsSize;i++) {
        printf("\t%08x\t%s\n",i,getTypeIdDataByIndex(i).c_str());
    }
    printf("TypeIds End\n");
}
void DexFile::printProtoIds() {
    printf("ProtoIds:\n");
    printf("\tNums\t\tProtoIds\n");
    for(int i=0;i<pHeader->protoIdsSize;i++) {
        printf("\t%08x\t%s\n",i,getProtoIdDataByIndex(i).c_str());
    }
    printf("ProtoIds End\n");
}
void DexFile::printFieldIds() {
    printf("FieldIds:\n");
    printf("\tNums\t\tFieldIds\n");
    for(int i=0;i<pHeader->fieldIdsSize;i++) {
        printf("\t%08x\t%s\n",i,getFieldIdDataByIndex(i).c_str());
    }
    printf("FieldId End\n");
}
void DexFile::printMethodIds() {
    printf("MethodIds:\n");
    printf("\tNums\t\tMethodIds\n");
    for(int i=0;i<pHeader->methodIdsSize;i++) {
        printf("\t%08x\t%s\n",i,getMethodIdDataByIndex(i).c_str());
    }
    printf("MethodIds End\n");
}
void DexFile::printMapList() {
    static std::map<int, std::string> MapItemTypeToStringMap = {
        {kDexTypeHeaderItem, "HeaderItem"},
        {kDexTypeStringIdItem, "StringIdItem"},
        {kDexTypeTypeIdItem, "TypeIdItem"},
        {kDexTypeProtoIdItem, "ProtoIdItem"},
        {kDexTypeFieldIdItem, "FieldIdItem"},
        {kDexTypeMethodIdItem, "MethodIdItem"},
        {kDexTypeClassDefItem, "ClassDefItem"},
        {kDexTypeMapList, "MapList"},
        {kDexTypeTypeList, "TypeList"},
        {kDexTypeAnnotationSetRefList, "AnnotationSetRefList"},
        {kDexTypeAnnotationSetItem, "AnnotationSetItem"},
        {kDexTypeClassDataItem, "ClassDataItem"},
        {kDexTypeCodeItem, "CodeItem"},
        {kDexTypeStringDataItem, "StringDataItem"},
        {kDexTypeDebugInfoItem, "DebugInfoItem"},
        {kDexTypeAnnotationItem, "AnnotationItem"},
        {kDexTypeEncodedArrayItem, "EncodedArrayItem"},
        {kDexTypeAnnotationsDirectoryItem, "AnnotationsDirectoryItem"}
    };

    DexMapList* pMapList=(DexMapList*)(baseAddr+pHeader->mapOff);
    DexMapItem* pMapItems=pMapList->list;
    printf("MapList has %d items, start at: %#x\n",pMapList->size,pHeader->mapOff);
    printf("Nums\t\tType\t\t\t\tItemNums\tStartOff\n");
    for(int i=0;i<pMapList->size;i++) {
        // 解析MapType
        auto it=MapItemTypeToStringMap.find(pMapItems[i].type);
        std::string mapType;
        if(it!= MapItemTypeToStringMap.end())
            mapType=it->second;
        else mapType="Unknown Type";
        printf("%08d\t%-24s\t%08d\t%08x\n",i+1,mapType.c_str(),pMapItems[i].size,pMapItems[i].offset);
    }
    printf("MapList End\n");
}

// ClassDef funtions
// ClassDef Basic Info functions
// 获取class
std::string DexFile::getClassDefClass(DexClassDef& classDef) {
    return parseString(getTypeIdDataByIndex(classDef.classIdx));
}
// 解析权限修饰符
std::string DexFile::parseAccessFlags(u4 accessFlags) {
    static std::map<int, std::string> AccessFlagMap = {
        {ACC_PUBLIC, "public"},
        {ACC_PRIVATE, "private"},
        {ACC_PROTECTED, "protected"},
        {ACC_STATIC, "static"},
        {ACC_FINAL, "final"},
        {ACC_SYNCHRONIZED, "synchronized"},
        {ACC_SUPER, "super"},
        {ACC_VOLATILE, "volatile"},
        {ACC_BRIDGE, "bridge"},
        {ACC_TRANSIENT, "transient"},
        {ACC_VARARGS, "varargs"},
        {ACC_NATIVE, "native"},
        {ACC_INTERFACE, "interface"},
        {ACC_ABSTRACT, "abstract"},
        {ACC_STRICT, "strict"},
        {ACC_SYNTHETIC, "synthetic"},
        {ACC_ANNOTATION, "annotation"},
        {ACC_ENUM, "enum"},
        {ACC_CONSTRUCTOR, "constructor"},
        {ACC_DECLARED_SYNCHRONIZED, "declared_synchronized"}
    };
    std::string result;
    for(int i=0;i<32;i++) {
        if(accessFlags & (1 << i)) {
            result+=AccessFlagMap[1 << i]+" ";//遍历添加权限控制属性
        }
    }
    if(!result.empty())
        result=result.substr(0,result.length()-1);//去除末尾多余空格
    return result;
}
// 获取父类
std::string DexFile::getClassDefSuperClass(DexClassDef& classDef) {
    return parseString(getTypeIdDataByIndex(classDef.superclassIdx));
}
// 获取接口列表
std::vector<std::string> DexFile::getClassDefInterfaces(DexClassDef& classDef) {
    std::vector<std::string> interfaces;
    //无参数
    if(classDef.interfacesOff==0) {
        return interfaces;
    }
    DexTypeList* typeList=(DexTypeList*)(baseAddr+classDef.interfacesOff);
    for(int i=0;i<typeList->size;i++) {
        interfaces.push_back(getTypeIdDataByIndex(typeList->list[i].typeIdx));
    }
    return interfaces;
}
// 获取源文件
std::string DexFile::getClassDefSourceFile(DexClassDef& classDef) {
    return getStringIdDataByIndex(classDef.sourceFileIdx);
}
// 打印ClassDef结构的基本信息: 类名 父类 源文件名 接口
void DexFile::printClassDefBasicInfo(DexClassDef& classDef) {
    std::string className=getClassDefClass(classDef);
    std::string accessFlags=parseAccessFlags(classDef.accessFlags);
    std::string superClass=getClassDefSuperClass(classDef);
    std::vector<std::string> interfaces=getClassDefInterfaces(classDef);
    std::string sourceFile=getClassDefSourceFile(classDef);

    // Basic info, class super_class source_file interfaces
    printf("Class:\t\t%s\n",combineAccFlagsAndName(accessFlags,className).c_str());
    printf("Super Class:\t%s\n",superClass.c_str());
    printf("Source File:\t%s\n",sourceFile.c_str());

    // print interfaces if have it
    if(!interfaces.empty()) {
        printf("Interfaces:\nNums\t\tInterface\n");
        for(int j=0;j<interfaces.size();j++) {
            printf("%08d\t%s\n",j+1,parseString(interfaces[j]).c_str());
        }
    }else {
        printf("No Interfaces\n");
    }
}

// 读取EncodedValue, 由于大小不固定, 故直接以数组赋值形式取值
void DexFile::getEncodedValue(ubyte* pDest,const ubyte* pValue,int size) {
    for(int i=0;i<size;i++) {
        pDest[i]=pValue[i];
    }
}
// 解析EncodedValue, 返回解析后的字符串以及value真实大小 Todo: 完善解析逻辑,剩余3个分支
std::string DexFile::parseEncodedValue(ubyte* pEncodedValue,size_t& valueRealSize) {
    ubyte valueArg = GetValueArg(pEncodedValue[0]);// arg=size-1,值占用的字节数<=对应类型大小,不含头部的单字节
    ubyte valueType = GetValueType(pEncodedValue[0]);
    // 假如int=0时,占2字节,头1字节,值0占1字节,所以要同时判断arg和type
    if(valueArg==0) {
        //arg==0时,要确定是arg固定为0的特殊类型还是其他类型
        //特殊类型只有1字节头,其他类型是1字节头+1字节数据
        bool isSpecialType=false;
        switch (valueType) {
            case VALUE_BYTE:
            case VALUE_ARRAY:
            case VALUE_ANNOTATION:
            case VALUE_NULL:
            case VALUE_BOOLEAN:
            isSpecialType=true;
            break;
        }
        if(isSpecialType)
            valueRealSize=1;
        else
            valueRealSize=2;
    }
    else
        valueRealSize=valueArg+2;// 头部1字节+实际大小 size=head+arg+1
    int readValueSize=valueArg+1;// 需要读取的字节数
    ubyte* pValue=&pEncodedValue[1];
    std::string result;
    unsigned int index=0;
    switch(valueType) {
        // 有符号单字节
        case VALUE_BYTE: {
            char byte=0;
            getEncodedValue((ubyte*)&byte,pValue,readValueSize);
            result="byte:"+std::format("0x{:x}",byte);
            break;
        }
        // 有符号双字节
        case VALUE_SHORT: {
            short value_short=0;
            getEncodedValue((ubyte*)&value_short,pValue,readValueSize);
            result="short:"+std::format("0x{:x}",value_short);
            break;
        }
        // 无符号双字节
        case VALUE_CHAR: {
            unsigned short value_char=0;
            getEncodedValue((ubyte*)&value_char,pValue,readValueSize);
            result="char:"+std::format("0x{:x}",value_char);
            break;
        }
        // 有符号4字节
        case VALUE_INT: {
            int value_int=0;
            getEncodedValue((ubyte*)&value_int,pValue,readValueSize);
            result="int:"+std::format("0x{:x}",value_int);
            break;
        }
        // 有符号8字节
        case VALUE_LONG: {
            long long value_long=0;
            getEncodedValue((ubyte*)&value_long,pValue,readValueSize);
            result="long:"+std::format("0x{:x}",value_long);
            break;
        }
        // 4字节浮点
        case VALUE_FLOAT: {
            float value_float=0;
            getEncodedValue((ubyte*)&value_float,pValue,readValueSize);
            result="float:"+std::format("{:f}",value_float);
            break;
        }
        // 8字节浮点
        case VALUE_DOUBLE: {
            double value_double=0;
            getEncodedValue((ubyte*)&value_double,pValue,readValueSize);
            result="double:"+std::format("{:f}",value_double);
            break;
        }
        // 无符号4字节索引 指向对应结构
        case VALUE_METHOD_TYPE: {
            // ProtoId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="MethodType:"+std::format("0x{:x}",index)+" "+getProtoIdDataByIndex(index);
            break;
        }
        // todo: 这部分没有定义的成员指向,暂时不知如何解析,参考 https://source.android.com/docs/core/runtime/dex-format?hl=zh-cn#method-handle-item
        case VALUE_METHOD_HANDLE: {
            // MethodHandles
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="MethodHandle Index:"+std::format("0x{:x}",index);
            break;
        }
        case VALUE_STRING: {
            // StringId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="String:"+getStringIdDataByIndex(index);
            break;
        }
        case VALUE_TYPE: {
            // TypeId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="Type:"+parseString(getTypeIdDataByIndex(index));
            break;
        }
        case VALUE_FIELD: {
            // FieldId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="Field:"+parseString(getFieldIdDataByIndex(index));
            break;
        }
        case VALUE_METHOD: {
            // MethodId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="Method:"+parseString(getMethodIdDataByIndex(index));
            break;
        }
        case VALUE_ENUM: {
            // FieldId
            getEncodedValue((ubyte*)&index,pValue,readValueSize);
            result="Enum:"+parseString(getFieldIdDataByIndex(index));
            break;
        }
        // todo encoded_array和encoded_annotation结构,不太容易解析
        case VALUE_ARRAY: {
            //getEncodedValue((ubyte*)&index,pValue,readValueSize);
            // DexEncodedArray encodedArray;//直接解析貌似不正确
            // getEncodedValue((ubyte*)&encodedArray,pValue,readValueSize);
            // printClassDefStaticValues(encodedArray);
            // int sizeLen=0;
            // u4 size=myReadUnsignedLeb128(pValue,&sizeLen);
            // u1* pValues=pValue+sizeLen;
            // printf("EncodedArray contains %d values\n",size);
            // unsigned int offset=0;// offset保存前方已访问的结构大小
            // for(int i=0;i<size;i++) {
            //     printf("%s\n",parseEncodedValue(pValues+offset,offset).c_str());
            // }
            //system("pause");
            break;
        }
        case VALUE_ANNOTATION:
        result="Todo......";
        break;
        case VALUE_NULL:
            result="null";
        break;
        // boolean的值存在value_arg中
        case VALUE_BOOLEAN:
            result="bool:";
            if(valueArg)
                result+="true";
            else
                result+="false";
            break;
        default:
            result="Unknown value type";
    }
    return result;
}

// Annotation functions
// 将权限修饰符和方法/类名组合
std::string DexFile::combineAccFlagsAndName(std::string accFlags,std::string name) {
    std::string result;
    if(accFlags.empty())
        result=name;//无权限控制关键字,完整名即可
    else
        result=accFlags+" "+name;
    return result;
}
// 打印DexAnnotationItem结构信息
void DexFile::printAnnotation(DexAnnotationItem& annotationItem) {
    std::string visibility;//注解可见性
    switch(annotationItem.visibility) {
        case kDexVisibilityBuild: visibility="build";break;
        case kDexVisibilityRuntime:visibility="runtime";break;
        case kDexVisibilitySystem:visibility="system";break;
        default:visibility="unknown";
    }
    // 解析encoded_annotation
    u1* pAnnotation=annotationItem.annotation;
    size_t typeSize=0,sizeSize=0;
    u4 encoded_annotation_type_idx=myReadUnsignedLeb128(pAnnotation,&typeSize);//注解类型偏移
    u4 encoded_annotation_size=myReadUnsignedLeb128(pAnnotation+typeSize,&sizeSize);//注解name-value映射数
    std::string encoded_annotation_type=parseString(getTypeIdDataByIndex(encoded_annotation_type_idx));

    //Size Visibility Type
    printf("%08d\t%s\t\t%s\n",encoded_annotation_size,visibility.c_str(),encoded_annotation_type.c_str());

    // 解析encoded_annotation.elements
    u1* pAnnotationElements=pAnnotation+typeSize+sizeSize;
    for(int i=0;i<encoded_annotation_size;i++) {
        size_t name_idx_size=0;// name_idx
        std::string name=parseString(getStringIdDataByIndex(myReadUnsignedLeb128(pAnnotationElements,&name_idx_size)));
        size_t valueSize=0;
        std::string value=parseString(parseEncodedValue(pAnnotationElements+name_idx_size,valueSize));
        printf("\t%s=%s\n",name.c_str(),value.c_str());
    }
}
// 打印DexAnnotationSetItem信息 即多个DexAnnotationItem结构
void DexFile::printAnnotationSet(DexAnnotationSetItem& annotationSet) {
    printf("Size\t\tVisibility\tType\n");
    //AnnotationSetItem.entries[] 数组保存AnnotationItem结构的文件偏移值
    for(int j=0;j<annotationSet.size;j++) {
        printAnnotation(*(DexAnnotationItem*)(annotationSet.entries[j]+baseAddr));
    }
}
// 打印所有类注解 DexAnnotationSetItem
void DexFile::printClassAnnotations(DexAnnotationSetItem& classAnnotations) {
    printf("Class Annotations start at %#llx, contains %d entries\n",(uintptr_t)classAnnotations.entries-(uintptr_t)baseAddr,classAnnotations.size);
    printAnnotationSet(classAnnotations);
    printf("Class Annotations End\n\n");
}

// 打印所有域注解 DexFieldAnnotationsItem
void DexFile::printFieldAnnotations(DexFieldAnnotationsItem* pFieldAnnotations,u4 fieldsNum) {
    printf("Field Annotations start at %#llx, contains %d entries\n",(uintptr_t)pFieldAnnotations-(uintptr_t)baseAddr,fieldsNum);
    for(int i=0;i<fieldsNum;i++) {
        std::string field=getFieldIdDataByIndex(pFieldAnnotations[i].fieldIdx);
        printf("Field%d:\t%s\n",i+1,field.c_str());
        printAnnotationSet(*(DexAnnotationSetItem*)(baseAddr+pFieldAnnotations[i].annotationsOff));
    }
    printf("Field Annotations End\n\n");
}
// 打印方法注解 DexMethodAnnotationsItem
void DexFile::printMethodAnnotations(DexMethodAnnotationsItem* pMethodAnnotations,u4 methodsNum) {
    printf("Method Annotations start at %#llx, contains %d entries\n",(uintptr_t) pMethodAnnotations-(uintptr_t)baseAddr,methodsNum);
    for(int i=0;i<methodsNum;i++) {
        std::string method=getMethodIdDataByIndex(pMethodAnnotations[i].methodIdx);
        printf("Method%d:\t%s\n",i+1,method.c_str());
        printAnnotationSet(*(DexAnnotationSetItem*)(baseAddr+ pMethodAnnotations[i].annotationsOff));
    }
    printf("Method Annotations End\n\n");
}
// 打印DexAnnotationSetRefList
void DexFile::printAnnotationSetRefList(DexAnnotationSetRefList& annotationSetRefList) {
    printf("AnnotationSetRefList contains %d AnnotationSetItems\n",annotationSetRefList.size);
    // AnnotationSetRefList.list是AnnotationSetRefItem数组
    DexAnnotationSetRefItem* pAnnotationSetRefItem=annotationSetRefList.list;
    for(int i=0;i<annotationSetRefList.size;i++) {
        if(!pAnnotationSetRefItem[i].annotationsOff) {
            printf("No This Annotation Set!\n");//可能存在空项
            continue;
        }
        //AnnotationSetRefItem.annotationsOff指向AnnotationSetItem结构
        printAnnotationSet(*(DexAnnotationSetItem*)(baseAddr+pAnnotationSetRefItem[i].annotationsOff));
    }
    printf("AnnotationSetRefList End\n");
}
// 打印参数注解 DexParameterAnnotationsItem
void DexFile::printParameterAnnotations(DexParameterAnnotationsItem* pParameterAnnotations,u4 parametersNum) {
    printf("Parameter Annotations start at %#llx, contains %d entries\n",(uintptr_t) pParameterAnnotations-(uintptr_t)baseAddr,parametersNum);
    for(int i=0;i<parametersNum;i++) {
        std::string method=getMethodIdDataByIndex(pParameterAnnotations[i].methodIdx);
        printf("Method%d:\t%s\n",i+1,method.c_str());
        // PatameterAnnotationsItem.annotationsOff指向DexAnnotationSetRefList结构,和其他三个不同
        printAnnotationSetRefList(*(DexAnnotationSetRefList*)(baseAddr+pParameterAnnotations[i].annotationsOff));
        printf("\n");
    }
    printf("Parameter Annotations End\n\n");
}
// 打印ClassDef的所有Annotations
void DexFile::printClassDefAnnotations(DexAnnotationsDirectoryItem& annotationsDirectory) {
    //1. 类注释
    if(annotationsDirectory.classAnnotationsOff)
        printClassAnnotations(*(DexAnnotationSetItem*)(baseAddr+annotationsDirectory.classAnnotationsOff));
    else
        printf("No Class Annotations\n\n");

    //2. 域(字段)注释
    if(annotationsDirectory.fieldsSize) {
        printFieldAnnotations(
            (DexFieldAnnotationsItem*)((uintptr_t)&annotationsDirectory
                +sizeof(DexAnnotationsDirectoryItem))
                ,annotationsDirectory.fieldsSize);
    }else
        printf("No Field Annotations\n\n");

    //3. 方法注释
    if(annotationsDirectory.methodsSize) {
        printMethodAnnotations(
            (DexMethodAnnotationsItem*)
            ((uintptr_t)&annotationsDirectory
            +sizeof(DexAnnotationsDirectoryItem)
            +sizeof(DexFieldAnnotationsItem)*annotationsDirectory.fieldsSize)
            ,annotationsDirectory.methodsSize);
    }else {
        printf("No Method Annotations\n\n");
    }
    //4. 参数注释
    if(annotationsDirectory.parametersSize) {
        printParameterAnnotations(
            (DexParameterAnnotationsItem*)((uintptr_t)&annotationsDirectory
            +sizeof(DexAnnotationsDirectoryItem)
            +sizeof(DexFieldAnnotationsItem)*annotationsDirectory.fieldsSize
            +sizeof(DexMethodAnnotationsItem)*annotationsDirectory.methodsSize)
            ,annotationsDirectory.parametersSize);
        system("pause");
    }else {
        printf("No Parameter Annotations\n\n");
    }
}

// 打印DexCode Todo: 解析DexCode字段
void DexFile::printDexCode(DexCode& dexCode) {
    // 打印基本信息
    printf("DexCode:\n");
    printf("RegsNum\t\tParamsNum\tOutsNum\t\tTriesNum\tDebugInfoOff\tInsnsNum\tInsnsOff\n");
    printf("%08d\t%08d\t%08d\t%08d\t%08x\t%08d\t%08x\n",dexCode.registersSize,dexCode.insSize,dexCode.outsSize,dexCode.triesSize,dexCode.debugInfoOff,dexCode.insnsSize,(uintptr_t)dexCode.insns-(uintptr_t)baseAddr);
    // 打印
    printf("DexCode End\n");
}
// 打印DexClassData的DexField项目 返回对应数组结构的大小
unsigned int DexFile::printClassDataItem(DexField* pFields,u4 fieldsNum) {
    u4 prevFieldIndex=0,offset=0;
    for(int i=0;i<fieldsNum;i++) {
        DexField*  pField=(DexField*)((uintptr_t)pFields+offset);
        // 注意由于内部元素为uleb128类型,所以DexField大小并不固定,需要计算
        size_t fieldIndexSize=0,accessFlagsValueSize=0;
        u4 fieldIndex=myReadUnsignedLeb128((u1*)pField,&fieldIndexSize);
        u4 accessFlagsValue=myReadUnsignedLeb128((u1*)pField+fieldIndexSize,&accessFlagsValueSize);

        std::string fieldName=getFieldIdDataByIndex(prevFieldIndex+fieldIndex);
        std::string accessFlags=parseAccessFlags(accessFlagsValue);
        printf("Field%d: %s\n",i+1,combineAccFlagsAndName(accessFlags,fieldName).c_str());

        prevFieldIndex+=fieldIndex;// 更新前一个filedIndex
        offset+=fieldIndexSize+accessFlagsValueSize;//当前数组结构的偏移
    }
    return offset;//返回当前数组大小
}
// 打印DexClassData的DexMethod项目 返回对应数组结构的大小
unsigned int DexFile::printClassDataItem(DexMethod* pMethods,u4 methodsNum)
{
    u4 prevMethodIndex=0,offset=0;
    for(int i=0;i<methodsNum;i++) {
        DexMethod* pMethod=(DexMethod*)((uintptr_t)pMethods+offset);
        size_t methodIndexSize=0,accessFlagsValueSize=0,codeOffSize=0;// 相比DexField多了codeOff,指向DexCode结构
        u4 methodIndex=myReadUnsignedLeb128((u1*)pMethod,&methodIndexSize);
        u4 accessFlagsValue=myReadUnsignedLeb128((u1*)pMethod+methodIndexSize,&accessFlagsValueSize);
        u4 codeOff=myReadUnsignedLeb128((u1*)pMethod+methodIndexSize+accessFlagsValueSize,&codeOffSize);

        std::string methodName=getMethodIdDataByIndex(prevMethodIndex+methodIndex);
        std::string accessFlags=parseAccessFlags(accessFlagsValue);
        printf("Method%d: %s\n",i+1,combineAccFlagsAndName(accessFlags,methodName).c_str());
        if(codeOff) {
            printf("CodeOff: %08x\n",codeOff);
            printDexCode(*(DexCode*)(baseAddr+codeOff));//打印codeOff指向的DexCode
        }
        else
            printf("No DexCode\n");
        prevMethodIndex+=methodIndex;
        offset+=methodIndexSize+accessFlagsValueSize+codeOffSize;
    }
    return offset;
}
// 打印DexClassData
void DexFile::printClassDefClassData(DexClassData& classData) {
    printf("ClassData:\n");
    // 1.解析DexClassDataHeader 获取各uleb128字段保存的长度
    const u1* pClassDataHeader=(u1*)&classData.header;
    const u1** pPClassDataHeader=&pClassDataHeader;
    u4 staticFieldsNum=readUnsignedLeb128(pPClassDataHeader);
    u4 instanceFieldsNum=readUnsignedLeb128(pPClassDataHeader);
    u4 directMethodsNum=readUnsignedLeb128(pPClassDataHeader);
    u4 virtualMethodsNum=readUnsignedLeb128(pPClassDataHeader);
    // pointer指向DexClassDataHeader后方第一个字节(即4个数组的内容),用于后续计算
    uintptr_t pointer=((uintptr_t)&classData+unsignedLeb128Size(staticFieldsNum)
                                +unsignedLeb128Size(instanceFieldsNum)
                                +unsignedLeb128Size(directMethodsNum)
                                +unsignedLeb128Size(virtualMethodsNum));

    // 2. 解析各个字段(判断是否存在对应字段)
    // 注意:
    // 1. fieldIdx和accessFlags均为uleb128类型
    // 2. 数组首个fieldIndex和methodIndex是正确的,后续index是相对前一个index的偏移值(大部分为1)
    // 3. 由于各个结构大小不固定,但是四个数组是连续的,所以要使用offset记录前方数据的大小
    unsigned int offset=0;

    if(staticFieldsNum) {
        printf("ClassData contains %d Static Fields:\n",staticFieldsNum);
        offset+=printClassDataItem((DexField*)(pointer+offset),staticFieldsNum);
        printf("Static Fields End\n");
    }
    else {
        printf("No Static Field\n");
    }

    if(instanceFieldsNum) {
        printf("ClassData contains %d Instance Fields:\n",instanceFieldsNum);
        offset+=printClassDataItem((DexField*)(pointer+offset),staticFieldsNum);
        printf("Instance Fields End\n");
    }
    else {
        printf("No Instance Field\n");
    }

    if(directMethodsNum) {
        printf("ClassData contains %d Directed Methods:\n",directMethodsNum);
        offset+=printClassDataItem((DexMethod*)(pointer+offset),directMethodsNum);
        printf("Directed Methods End\n");
    }
    else {
        printf("No Directed Method\n");
    }

    if(virtualMethodsNum) {
        printf("ClassData contains %d Virtual Methods:\n",virtualMethodsNum);
        offset+=printClassDataItem((DexMethod*)(pointer+offset),virtualMethodsNum);
        printf("Virtual Methods End\n");
    }
    else {
        printf("No Virtual Method\n");
    }
    printf("ClassData End\n");
}

// 打印StaticValues 实际为DexEncodedArray结构
void DexFile::printClassDefStaticValues(DexEncodedArray& encodedArray) {
    size_t sizeLen=0;
    u4 size=myReadUnsignedLeb128((u1*)&encodedArray,&sizeLen);
    u1* pValues=(u1*)&encodedArray+sizeLen;
    printf("StaticValues contains %d values\n",size);
    size_t offset=0,readSize=0;// offset保存前方已访问的结构大小
    for(int i=0;i<size;i++) {
        printf("%s\n",parseEncodedValue(pValues+offset,readSize).c_str());
        offset+=readSize;
    }
    printf("StaticValues End\n");
}

// 打印所有ClassDef信息
void DexFile::printClassDefs() {
    printf("ClassDefs:\n");
    for(int i=0;i<pHeader->classDefsSize;i++) {
        DexClassDef classDef=pClassDefs[i];
        // 1.Basic info
        printf("=========================ClassDef %08d=========================\n",i+1);
        printClassDefBasicInfo(classDef);

        // 2. Annotations
        if(classDef.annotationsOff) {
            printf("Annotations:\n");
            printClassDefAnnotations(*(DexAnnotationsDirectoryItem*)(baseAddr+classDef.annotationsOff));
                // 值传递只保留前16字节导致内存访问错,需要引用传递
                // DexAnnotationsDirectoryItem annotations_directory_item=*(DexAnnotationsDirectoryItem*)(baseAddr+classDef.annotationsOff);
                // parseClassDefAnnotations(annotations_directory_item);
        }
        else
            printf("No Annotations\n");
        // 3. ClassData
        if(classDef.classDataOff) {
            printClassDefClassData(*(DexClassData*)(baseAddr+classDef.classDataOff));
        }else
            printf("No ClassData\n");
        // 4. StaticValues
        if(classDef.staticValuesOff) {
            printClassDefStaticValues(*(DexEncodedArray*)(baseAddr+classDef.staticValuesOff));
        }else
            printf("No StaticValues\n");
        printf("===================================================================\n");
    }
    printf("ClassDefs End\n");
}
