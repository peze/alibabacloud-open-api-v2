// This file is auto-generated, don't edit it. Thanks.
#ifndef ALIBABACLOUD_EXCEPTIONS_ALIBABACLOUDEXCEPTION_HPP_
#define ALIBABACLOUD_EXCEPTIONS_ALIBABACLOUDEXCEPTION_HPP_
#include <darabonba/Core.hpp>
#include <darabonba/Exception.hpp>
using namespace std;
using json = nlohmann::json;
namespace AlibabaCloud
{
namespace OpenApi
{
namespace Exceptions
{
  class AlibabaCloudException : public Darabonba::ResponseException {
  public:
    friend void from_json(const Darabonba::Json& j, AlibabaCloudException& obj) { 
      DARABONBA_PTR_FROM_JSON(statusCode, statusCode_);
      DARABONBA_PTR_FROM_JSON(code, code_);
      DARABONBA_PTR_FROM_JSON(message, message_);
      DARABONBA_PTR_FROM_JSON(description, description_);
      DARABONBA_PTR_FROM_JSON(requestId, requestId_);
    };
    AlibabaCloudException() ;
    AlibabaCloudException(const AlibabaCloudException &) = default ;
    AlibabaCloudException(AlibabaCloudException &&) = default ;
    AlibabaCloudException(const Darabonba::Json & obj) : Darabonba::ResponseException(obj) { from_json(obj, *this); };
    virtual ~AlibabaCloudException() = default ;
    AlibabaCloudException& operator=(const AlibabaCloudException &) = default ;
    AlibabaCloudException& operator=(AlibabaCloudException &&) = default ;
    inline int64_t statusCode() const { DARABONBA_PTR_GET_DEFAULT(statusCode_, 0) };
    inline string code() const { DARABONBA_PTR_GET_DEFAULT(code_, "") };
    inline string message() const { DARABONBA_PTR_GET_DEFAULT(message_, "") };
    inline string description() const { DARABONBA_PTR_GET_DEFAULT(description_, "") };
    inline string requestId() const { DARABONBA_PTR_GET_DEFAULT(requestId_, "") };
  protected:
    // HTTP Status Code
    std::shared_ptr<int64_t> statusCode_ = nullptr;
    // Error Code
    std::shared_ptr<string> code_ = nullptr;
    // Error Message
    std::shared_ptr<string> message_ = nullptr;
    // Error Description
    std::shared_ptr<string> description_ = nullptr;
    // Request ID
    std::shared_ptr<string> requestId_ = nullptr;
  };
  
  } // namespace Exceptions
} // namespace AlibabaCloud
} // namespace OpenApi
#endif
