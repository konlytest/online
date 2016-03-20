/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 100 -*- */
/*
 * This file is part of the LibreOffice project.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef INCLUDED_FILE_SERVER_HPP
#define INCLUDED_FILE_SERVER_HPP

#include <string>
#include <vector>

#include <Poco/Net/NetException.h>

#include <Poco/Net/HTTPCookie.h>
#include <Poco/Net/HTTPBasicCredentials.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/Runnable.h>
#include <Poco/StringTokenizer.h>
#include <Poco/URI.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/Util/Timer.h>

#include "Common.hpp"
#include "LOOLWSD.hpp"

using Poco::Net::HTTPRequest;
using Poco::Net::HTTPRequestHandler;
using Poco::Net::HTTPRequestHandlerFactory;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPServerParams;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::SecureServerSocket;
using Poco::Net::HTTPBasicCredentials;
using Poco::Util::Application;

class FileServerRequestHandler: public HTTPRequestHandler
{
public:
    FileServerRequestHandler()
    { }

    void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) override
    {
        assert(request.serverAddress().port() == FILE_SERVER_PORT);

        try
        {
            Poco::URI requestUri(request.getURI());
            std::vector<std::string> requestSegments;
            requestUri.getPathSegments(requestSegments);

            // TODO: We might want to package all files from leaflet to some other dir and restrict
            // file serving to it (?)
            const std::string endPoint = requestSegments[requestSegments.size() - 1];

            if (request.getMethod() == HTTPRequest::HTTP_GET)
            {
                // FIXME: Some nice way to ask for credentials for protected files
                if (endPoint == "admin.html" ||
                    endPoint == "adminSettings.html" ||
                    endPoint == "adminAnalytics.html")
                {
                    HTTPBasicCredentials credentials(request);
                    // TODO: Read username and password from config file
                    if (credentials.getUsername() == "admin"
                        && credentials.getPassword() == "admin")
                    {
                        const std::string htmlMimeType = "text/html";
                        // generate and set the cookie
                        const std::string keyPath = Poco::Path(Application::instance().commandPath()).parent().toString() + SSL_KEY_FILE;
                        JWTAuth authAgent(keyPath, "admin", "admin", "admin");
                        const std::string jwtToken = authAgent.getAccessToken();
                        Poco::Net::HTTPCookie cookie("jwt", jwtToken);
                        response.addCookie(cookie);
                        response.setContentType(htmlMimeType);
                        response.sendFile(LOOLWSD::FileServerRoot + requestUri.getPath(), htmlMimeType);
                    }
                    else
                    {
                        Log::info("Wrong admin credentials.");
                        throw Poco::Net::NotAuthenticatedException("Wrong credentials.");
                    }
                }
                else
                {
                    const std::string filePath = requestUri.getPath();
                    const std::size_t extPoint = endPoint.find_last_of(".");
                    if (extPoint == std::string::npos)
                        throw Poco::FileNotFoundException("Invalid file.");

                    const std::string fileType = endPoint.substr(extPoint + 1);
                    std::string mimeType;
                    if (fileType == "js")
                        mimeType = "application/javascript";
                    else if (fileType == "css")
                        mimeType = "text/css";
                    else if (fileType == "html")
                        mimeType = "text/html";
                    else
                        mimeType = "text/plain";

                    response.setContentType(mimeType);
                    response.sendFile(LOOLWSD::FileServerRoot + requestUri.getPath(), mimeType);
                }
            }
        }
        catch (Poco::Net::NotAuthenticatedException& exc)
        {
            Log::info ("FileServerRequestHandler::NotAuthenticated");
            response.set("WWW-Authenticate", "Basic realm=\"online\"");
            response.setStatus(HTTPResponse::HTTP_UNAUTHORIZED);
            response.setContentLength(0);
            response.send();
        }
        catch (Poco::FileNotFoundException& exc)
        {
            Log::info("FileServerRequestHandler:: File " + request.getURI() + " not found.");
            response.setStatus(HTTPResponse::HTTP_NOT_FOUND);
            response.setContentLength(0);
            response.send();
        }
    }
};

class FileServerRequestHandlerFactory: public HTTPRequestHandlerFactory
{
public:
    FileServerRequestHandlerFactory()
    {    }

    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override
    {
        auto logger = Log::info();
        logger << "Request from " << request.clientAddress().toString() << ": "
               << request.getMethod() << " " << request.getURI() << " "
               << request.getVersion();

        for (HTTPServerRequest::ConstIterator it = request.begin(); it != request.end(); ++it)
        {
            logger << " / " << it->first << ": " << it->second;
        }

        logger << Log::end;

        return new FileServerRequestHandler();
    }
};

/// A HTTP(S) file server
class FileServer : public Poco::Runnable
{
public:
    FileServer()
        : _srv(new FileServerRequestHandlerFactory(),
               SecureServerSocket(FILE_SERVER_PORT),
               new HTTPServerParams)
    {
        Log::info("HTTP File server ctor.");
    }

    ~FileServer()
    {
        Log::info("HTTP File Server dtor.");
        _srv.stopAll();
    }

    void run()
    {
        Log::info ("HTTP File server listening on " + std::to_string(FILE_SERVER_PORT));
        _srv.start();
    }

private:
    Poco::Net::HTTPServer _srv;
};

#endif

/* vim:set shiftwidth=4 softtabstop=4 expandtab: */
