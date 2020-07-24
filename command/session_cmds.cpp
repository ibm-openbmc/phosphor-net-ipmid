#include "session_cmds.hpp"

#include "endian.hpp"
#include "main.hpp"

#include <ipmid/api.h>

namespace command
{

std::vector<uint8_t>
    setSessionPrivilegeLevel(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler)
{
    auto request =
        reinterpret_cast<const SetSessionPrivLevelReq*>(inPayload.data());
    if (inPayload.size() != sizeof(*request))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    std::vector<uint8_t> outPayload(sizeof(SetSessionPrivLevelResp));
    auto response =
        reinterpret_cast<SetSessionPrivLevelResp*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint8_t reqPrivilegeLevel = request->reqPrivLevel;

    auto session = std::get<session::Manager&>(singletonPool)
                       .getSession(handler.sessionID);

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = session->currentPrivilege();
        return outPayload;
    }
    if (reqPrivilegeLevel > (static_cast<uint8_t>(session->reqMaxPrivLevel) &
                             session::reqMaxPrivMask))
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
        return outPayload;
    }
    // Use the minimum privilege of user or channel
    uint8_t minPriv = 0;
    if (session->sessionChannelAccess.privLimit <
        session->sessionUserPrivAccess.privilege)
    {
        minPriv = session->sessionChannelAccess.privLimit;
    }
    else
    {
        minPriv = session->sessionUserPrivAccess.privilege;
    }
    if (reqPrivilegeLevel > minPriv)
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }
    else
    {
        // update current privilege of the session.
        session->currentPrivilege(static_cast<uint8_t>(reqPrivilegeLevel));
        response->newPrivLevel = reqPrivilegeLevel;
    }

    return outPayload;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler)
{
    // minimum inPayload size is reqSessionId (uint32_t)
    // maximum inPayload size is struct CloseSessionRequest
    if (inPayload.size() != sizeof(uint32_t) &&
        inPayload.size() != sizeof(CloseSessionRequest))
    {
        std::vector<uint8_t> errorPayload{IPMI_CC_REQ_DATA_LEN_INVALID};
        return errorPayload;
    }

    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());

    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint32_t reqSessionId = request->sessionID;
    uint8_t reqSessionHandle = session::invalidSessionHandle;

    if (inPayload.size() == sizeof(CloseSessionRequest))
    {
        reqSessionHandle = request->sessionHandle;
    }

    if (reqSessionId == session::sessionZero &&
        reqSessionHandle == session::invalidSessionHandle)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
        return outPayload;
    }

    if (inPayload.size() == sizeof(reqSessionId) &&
        reqSessionId == session::sessionZero)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
        return outPayload;
    }

    auto bmcSessionID = endian::from_ipmi(request->sessionID);

    // Session 0 is needed to handle session setup, so session zero is never
    // closed
    if (bmcSessionID == session::sessionZero)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
    }
    else
    {
        auto status = std::get<session::Manager&>(singletonPool)
                          .stopSession(bmcSessionID);
        if (!status)
        {
            response->completionCode = IPMI_CC_INVALID_SESSIONID;
        }
    }
    return outPayload;
}

} // namespace command
