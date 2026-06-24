#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

class BusinessService {
public:
    void ExportAttachment(const char* fileName) {
        char command[512];
        sprintf(command, "zip /tmp/export.zip %s", fileName);
        system(command);
    }

    void CopyField(const char* input) {
        char buffer[64];
        strcpy(buffer, input);
    }

    std::string QueryAccount(const std::string& accountId) {
        std::string sql = "select * from S_ORG_EXT where ROW_ID = '" + accountId + "'";
        return sql;
    }

    char* AllocateLegacyBuffer() {
        return new char[1024];
    }
};

