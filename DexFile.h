//
// Created by admin on 2024/12/19.
//
#ifndef DEXFILE_H
#define DEXFILE_H

#include <cstdint>
#include <string>
#include <vector>


typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

/*
 * 160-bit SHA-1 digest.
 */
enum { kSHA1DigestLen = 20,
       kSHA1DigestOutputLen = kSHA1DigestLen*2 +1,
        /* general constants */
        kDexEndianConstant = 0x12345678,    /* the endianness indicator */
        kDexNoIndex = 0xffffffff,           /* not a valid index value */
};


/*
 * access flags and masks; the "standard" ones are all <= 0x4000
 *
 * Note: There are related declarations in vm/oo/Object.h in the ClassFlags
 * enum.
 */
enum {
    ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE      = 0x00000002,       // field, method, ic
    ACC_PROTECTED    = 0x00000004,       // field, method, ic
    ACC_STATIC       = 0x00000008,       // field, method, ic
    ACC_FINAL        = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040,       // field
    ACC_BRIDGE       = 0x00000040,       // method (1.5)
    ACC_TRANSIENT    = 0x00000080,       // field
    ACC_VARARGS      = 0x00000080,       // method (1.5)
    ACC_NATIVE       = 0x00000100,       // method
    ACC_INTERFACE    = 0x00000200,       // class, ic
    ACC_ABSTRACT     = 0x00000400,       // class, method, ic
    ACC_STRICT       = 0x00000800,       // method
    ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
    ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
    ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =(ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT| ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =(ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =(ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL| ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =(ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL| ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED),
};

/* annotation constants */
enum {
    kDexVisibilityBuild         = 0x00,     /* annotation visibility */
    kDexVisibilityRuntime       = 0x01,
    kDexVisibilitySystem        = 0x02,

    kDexAnnotationByte          = 0x00,
    kDexAnnotationShort         = 0x02,
    kDexAnnotationChar          = 0x03,
    kDexAnnotationInt           = 0x04,
    kDexAnnotationLong          = 0x06,
    kDexAnnotationFloat         = 0x10,
    kDexAnnotationDouble        = 0x11,
    kDexAnnotationString        = 0x17,
    kDexAnnotationType          = 0x18,
    kDexAnnotationField         = 0x19,
    kDexAnnotationMethod        = 0x1a,
    kDexAnnotationEnum          = 0x1b,
    kDexAnnotationArray         = 0x1c,
    kDexAnnotationAnnotation    = 0x1d,
    kDexAnnotationNull          = 0x1e,
    kDexAnnotationBoolean       = 0x1f,

    kDexAnnotationValueTypeMask = 0x1f,     /* low 5 bits */
    kDexAnnotationValueArgShift = 5,
};

/* map item type codes */
enum {
    kDexTypeHeaderItem               = 0x0000,
    kDexTypeStringIdItem             = 0x0001,
    kDexTypeTypeIdItem               = 0x0002,
    kDexTypeProtoIdItem              = 0x0003,
    kDexTypeFieldIdItem              = 0x0004,
    kDexTypeMethodIdItem             = 0x0005,
    kDexTypeClassDefItem             = 0x0006,
    kDexTypeMapList                  = 0x1000,
    kDexTypeTypeList                 = 0x1001,
    kDexTypeAnnotationSetRefList     = 0x1002,
    kDexTypeAnnotationSetItem        = 0x1003,
    kDexTypeClassDataItem            = 0x2000,
    kDexTypeCodeItem                 = 0x2001,
    kDexTypeStringDataItem           = 0x2002,
    kDexTypeDebugInfoItem            = 0x2003,
    kDexTypeAnnotationItem           = 0x2004,
    kDexTypeEncodedArrayItem         = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};
enum {
    VALUE_BYTE=0x00,
    VALUE_SHORT=0x02,
    VALUE_CHAR=0x03,
    VALUE_INT=0x04,
    VALUE_LONG=0x06,
    VALUE_FLOAT=0x10,
    VALUE_DOUBLE=0x11,
    VALUE_METHOD_TYPE=0x15,
    VALUE_METHOD_HANDLE=0x16,
    VALUE_STRING=0x17,
    VALUE_TYPE=0x18,
    VALUE_FIELD=0x19,
    VALUE_METHOD=0x1a,
    VALUE_ENUM=0x1b,
    VALUE_ARRAY=0x1c,
    VALUE_ANNOTATION=0x1d,
    VALUE_NULL=0x1e,
    VALUE_BOOLEAN=0x1f
};

#define GetValueArg(x) (x>>5)
#define GetValueType(x) (x&0x1F)
typedef unsigned char ubyte;


/* auxillary data section chunk codes */
enum {
    kDexChunkClassLookup            = 0x434c4b50,   /* CLKP */
    kDexChunkRegisterMaps           = 0x524d4150,   /* RMAP */
    kDexChunkEnd                    = 0x41454e44,   /* AEND */
};

//Direct-mapped "header_item" struct.
struct DexHeader {
    u1  magic[8];			//Dex版本号 dex.035 .035即为版本号
    u4  checksum;           //adler32检验,如果修改了Dex文件,需要修正这个值,否则会运行不起来
    u1  signature[kSHA1DigestLen]; //SHA-1值,Android不检测该值,但如果修改了Dex文件,最好修复该值,再修checksum
    u4  fileSize;           //整个dex文件的大小
    u4  headerSize;         //DexHeader结构的大小,固定为0x70
    u4  endianTag;          //字节序标记,若该字段按小端方式读出来为0x12345678,则整个Dex文件就是小端方式.如果按大端方式读出来为0x12345678,那整个Dex文件就是大端方式
    u4  linkSize;			//链接段大小
    u4  linkOff;			//链接段偏移
    u4  mapOff;				//DexMapList文件偏移
    u4  stringIdsSize;		//DexStringId个数
    u4  stringIdsOff;		//DexStringId文件偏移
    u4  typeIdsSize;		//DexTypeId个数
    u4  typeIdsOff;			//DexTypeId文件偏移
    u4  protoIdsSize;		//DexProtoId个数
    u4  protoIdsOff;		//DexProtoId文件偏移
    u4  fieldIdsSize;		//DexFieldId个数
    u4  fieldIdsOff;		//DexFieldId文件偏移
    u4  methodIdsSize;		//DexMethodId个数
    u4  methodIdsOff;		//DexMethodId文件偏移
    u4  classDefsSize;		//DexClassDef个数
    u4  classDefsOff;		//DexClassDef文件偏移
    u4  dataSize;			//数据段大小
    u4  dataOff;			//数据段文件偏移
};

//Direct-mapped "map_item".
typedef struct DexMapItem {
    u2  type;              /* type code (see kDexType* above) */
    u2  unused;
    u4  size;              /* count of items of the indicated type */
    u4  offset;            /* file offset to the start of data */
} DexMapItem;

//Direct-mapped "map_list".
typedef struct DexMapList {
    u4  size;               /* #of entries in list */
    DexMapItem list[1];     /* entries */
} DexMapList;

//Direct-mapped "string_id_item".
typedef struct DexStringId {
    u4  stringDataOff;      /* file offset to string_data_item */
} DexStringId;

//Direct-mapped "type_id_item".
typedef struct DexTypeId {
    u4  descriptorIdx;      /* index into stringIds list for type descriptor */
} DexTypeId;

//Direct-mapped "field_id_item".
typedef struct DexFieldId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  typeIdx;            /* index into typeIds for field type */
    u4  nameIdx;            /* index into stringIds for field name */
} DexFieldId;


//Direct-mapped "method_id_item".
typedef struct DexMethodId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  protoIdx;           /* index into protoIds for method prototype */
    u4  nameIdx;            /* index into stringIds for method name */
} DexMethodId;

//Direct-mapped "proto_id_item".
typedef struct DexProtoId {
    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
    u4  returnTypeIdx;      /* index into typeIds list for return type */
    u4  parametersOff;      /* file offset to type_list for parameter types */
} DexProtoId;

//Direct-mapped "class_def_item".
typedef struct DexClassDef {
    u4  classIdx;           /* index into typeIds for this class */
    u4  accessFlags;
    u4  superclassIdx;      /* index into typeIds for superclass */
    u4  interfacesOff;      /* file offset to DexTypeList */
    u4  sourceFileIdx;      /* index into stringIds for source file name */
    u4  annotationsOff;     /* file offset to annotations_directory_item */
    u4  classDataOff;       /* file offset to class_data_item */
    u4  staticValuesOff;    /* file offset to DexEncodedArray */
} DexClassDef;


//Direct-mapped "type_item".
typedef struct DexTypeItem {
    u2  typeIdx;            /* index into typeIds */
} DexTypeItem;

//Direct-mapped "type_list".
typedef struct DexTypeList {
    u4  size;               /* #of entries in list */
    DexTypeItem list[1];    /* entries */
} DexTypeList;

/*
 * Direct-mapped "code_item".
 *
 * The "catches" table is used when throwing an exception,
 * "debugInfo" is used when displaying an exception stack trace or
 * debugging. An offset of zero indicates that there are no entries.
 */
typedef struct DexCode {
    u2  registersSize;
    u2  insSize;
    u2  outsSize;
    u2  triesSize;
    u4  debugInfoOff;       /* file offset to debug info stream */
    u4  insnsSize;          /* size of the insns array, in u2 units */
    u2  insns[1];
    /* followed by optional u2 padding */
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
} DexCode;

/*
 * Direct-mapped "try_item".
 */
typedef struct DexTry {
    u4  startAddr;          /* start address, in 16-bit code units */
    u2  insnCount;          /* instruction count, in 16-bit code units */
    u2  handlerOff;         /* offset in encoded handler data to handlers */
} DexTry;

/*
 * Link table.  Currently undefined.
 */
typedef struct DexLink {
    u1  bleargh;
} DexLink;


/*
 * Direct-mapped "annotations_directory_item".
 */
typedef struct DexAnnotationsDirectoryItem {
    u4  classAnnotationsOff;  /* offset to DexAnnotationSetItem */
    u4  fieldsSize;           /* count of DexFieldAnnotationsItem */
    u4  methodsSize;          /* count of DexMethodAnnotationsItem */
    u4  parametersSize;       /* count of DexParameterAnnotationsItem */
    /* followed by DexFieldAnnotationsItem[fieldsSize] */
    /* followed by DexMethodAnnotationsItem[methodsSize] */
    /* followed by DexParameterAnnotationsItem[parametersSize] */
} DexAnnotationsDirectoryItem;

/*
 * Direct-mapped "field_annotations_item".
 */
typedef struct DexFieldAnnotationsItem {
    u4  fieldIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexFieldAnnotationsItem;

/*
 * Direct-mapped "method_annotations_item".
 */
typedef struct DexMethodAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexMethodAnnotationsItem;

/*
 * Direct-mapped "parameter_annotations_item".
 */
typedef struct DexParameterAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnotationSetRefList */
} DexParameterAnnotationsItem;

/*
 * Direct-mapped "annotation_set_ref_item".
 */
typedef struct DexAnnotationSetRefItem {
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
} DexAnnotationSetRefItem;

/*
 * Direct-mapped "annotation_set_ref_list".
 */
typedef struct DexAnnotationSetRefList {
    u4  size;
    DexAnnotationSetRefItem list[1];
} DexAnnotationSetRefList;

/*
 * Direct-mapped "anotation_set_item".
 */
typedef struct DexAnnotationSetItem {
    u4  size;
    u4  entries[1];                 /* offset to DexAnnotationItem */
} DexAnnotationSetItem;

/*
 * Direct-mapped "annotation_item".
 *
 * NOTE: this structure is byte-aligned.
 */
typedef struct DexAnnotationItem {
    u1  visibility;
    u1  annotation[1];              /* data in encoded_annotation format */
} DexAnnotationItem;

/* expanded form of a class_data_item header */
typedef struct DexClassDataHeader {
    u4 staticFieldsSize;
    u4 instanceFieldsSize;
    u4 directMethodsSize;
    u4 virtualMethodsSize;
} DexClassDataHeader;

/* expanded form of encoded_field */
typedef struct DexField {
    u4 fieldIdx;    /* index to a field_id_item */
    u4 accessFlags;
} DexField;

/* expanded form of encoded_method */
typedef struct DexMethod {
    u4 methodIdx;    /* index to a method_id_item */
    u4 accessFlags;
    u4 codeOff;      /* file offset to a code_item */
} DexMethod;

/* expanded form of class_data_item. Note: If a particular item is
 * absent (e.g., no static fields), then the corresponding pointer
 * is set to NULL. */
typedef struct DexClassData {
    DexClassDataHeader header;
    DexField*          staticFields;
    DexField*          instanceFields;
    DexMethod*         directMethods;
    DexMethod*         virtualMethods;
} DexClassData;

/*
 * Direct-mapped "encoded_array".
 *
 * NOTE: this structure is byte-aligned.
 */
typedef struct DexEncodedArray {
    u1  array[1];                   /* data in encoded_array format */
} DexEncodedArray;

class DexFile {
    u1*           baseAddr{nullptr};
    DexHeader*    pHeader{nullptr};
    DexStringId*  pStringIds{nullptr};
    DexTypeId*    pTypeIds{nullptr};
    DexFieldId*   pFieldIds{nullptr};
    DexMethodId*  pMethodIds{nullptr};
    DexProtoId*   pProtoIds{nullptr};
    DexClassDef*  pClassDefs{nullptr};
    void initFields(unsigned char *buffer);

    std::string parseEncodedValue(ubyte *pEncodedValue, size_t &valueRealSize);

public:
    DexFile(unsigned char* buffer);
    DexFile(std::string filePath);
    ~DexFile();

    void printDexHeader();
    void printStringIds();
    void printTypeIds();
    void printProtoIds();
    void printFieldIds();
    void printMethodIds();
    void printMapList();
    void printClassDefs();

    size_t getStringDataLength(DexStringId &stringId);
    std::string parseAccessFlags(u4 accessFlags);
    std::string parseAccessFlag(u4 accessFlag);
    std::string getClassDefClassWithAccFlags(DexClassDef &classDef);
    void printAnnotation(DexAnnotationItem &annotationItem);
    void printAnnotationSet(DexAnnotationSetItem &annotationSet);
    void printClassAnnotations(DexAnnotationSetItem &classAnnotations);
    void printFieldAnnotations(DexFieldAnnotationsItem *pFieldAnnotations, u4 fieldsNum);
    void printMethodAnnotations(DexMethodAnnotationsItem *pMethodAnnotations, u4 methodsNum);
    void printAnnotationSetRefList(DexAnnotationSetRefList &annotationSetRefList);
    void printParameterAnnotations(DexParameterAnnotationsItem *pParameterAnnotations, u4 parametersNum);
    std::string getAnnotationVisibility(DexAnnotationItem &annotationItem);
    std::string getAnnotationType(DexAnnotationItem &annotationItem);
    void parseClassAnnotations(DexAnnotationItem annotationItem, size_t nums);
    void parseFieldAnnotations(DexFieldAnnotationsItem &fieldAnnotationsItem, size_t nums);
    void parseMethodAnnotations(DexMethodAnnotationsItem &methodAnnotationsItem, size_t nums);
    void parseParameterAnnotaions(DexParameterAnnotationsItem &parameterAnnotationsItem, size_t nums);
    void printClassDefAnnotations(DexAnnotationsDirectoryItem &annotationsDirectory);
    void printDexCode(DexCode &dexCode);
    unsigned int printClassDataItem(DexField *pFields, u4 fieldsNum);
    unsigned int printClassDataItem(DexMethod *pMethods, u4 methodsNum);
    void printClassDefClassData(DexClassData &classData);
    void getEncodedValue(ubyte *pDest, const ubyte *pValue, int size);
    void printClassDefStaticValues(DexEncodedArray &encodedArray);
    void printClassDefBasicInfo(DexClassDef &classDef);
    std::string parseFieldId(const DexFieldId &fieldId);
    std::string getFieldIdDataByIndex(u4 index);
    std::string parseMethodId(const DexMethodId &methodId);
    std::string getMethodIdDataByIndex(u4 index);
    std::string getClassDefClass(DexClassDef &classDef);
    std::string getClassDefSuperClass(DexClassDef &classDef);
    std::vector<std::string> getClassDefInterfaces(DexClassDef &classDef);
    std::string getClassDefSourceFile(DexClassDef &classDef);
    std::string combineAccFlagsAndName(std::string accFlags, std::string name);
    std::string parseShorty();
    std::string parseReturnType(std::string return_type);
    std::string parseString(std::string input);
    std::string parseParameters(std::vector<std::string> parameters);
    std::string parseProtoId(const DexProtoId &protoId);
    std::string getProtoIdDataByIndex(u4 index);
    std::string getStringIdData(const DexStringId& pStringId);
    DexStringId getStringIdByIndex(u4 index);
    std::string getStringIdDataByIndex(u4 index);
    DexTypeId getTypeIdByIndex(u4 index);
    const char *getTypeIdData(const DexTypeId &typeId);
    std::string getTypeIdDataByIndex(u4 index);
    const DexProtoId getProtoIdByIndex(u4 index);
    std::string getProtoIdShorty(const DexProtoId &protoId);
    std::string getProtoIdReturnType(const DexProtoId &protoId);
    std::vector<std::string> getProtoIdParameters(const DexProtoId &protoId);
    const DexFieldId getFieldIdByIndex(u4 index);
    std::string getFieldIdClass(const DexFieldId &fieldId);
    std::string getFieldIdType(const DexFieldId &fieldId);
    std::string getFieldIdName(const DexFieldId &fieldId);
    const DexMethodId getMethodIdByIndex(u4 index);
    std::string getMethodIdClass(const DexMethodId &methodId);
    std::string getMethodIdProto(const DexMethodId &methodId);
    std::string getMethodIdName(const DexMethodId &methodId);
};

#endif //DEXFILE_H
