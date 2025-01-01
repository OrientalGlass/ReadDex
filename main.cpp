#include <iostream>
#include "DexFile.h"
#include <cstdlib>

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string filePath;
    //std::string filePath=R"(E:\KnowledgeRepository\Android\DexFileStructure\NetEase_classes2.dex)";
    //DexFile dexfile(filePath);
    //测试
    //dexfile.printDexHeader();
    //dexfile.printStringIds();
    //dexfile.printTypeIds();
    //dexfile.printProtoIds();
    //dexfile.printFieldIds();
    //dexfile.printMethodIds();
    //dexfile.printMapList();
    //dexfile.printClassDefs();
    // 寻找文件路径
    for(int i=0;i<args.size();i++) {
        if(args[i].find("-file") != std::string::npos) {
            filePath=args[++i];
        }
    }
    if(filePath.empty()) {
        std::cout<<"File path is empty!\n"<<std::endl;
        exit(0);
    }
    DexFile dexfile(filePath);
    // 解析参数,执行对应操作
    for (const auto& arg : args) {
        if(arg=="-file") {
            std::cout<<"File Path: "<<filePath<<std::endl;
        }
        else if (arg == "-header") {
            dexfile.printDexHeader();
        } else if (arg == "-strings") {
            dexfile.printStringIds();
        } else if (arg == "-types") {
            dexfile.printTypeIds();
        } else if (arg == "-protos") {
            dexfile.printProtoIds();
        } else if (arg == "-fields") {
            dexfile.printFieldIds();
        } else if (arg == "-methods") {
            dexfile.printMethodIds();
        } else if (arg == "-maplist") {
            dexfile.printMapList();
        } else if (arg == "-classdefs") {
            dexfile.printClassDefs();
        } else {
            std::cout << "Unknown arg:" << arg << std::endl;
        }
    }
    return 0;
}
