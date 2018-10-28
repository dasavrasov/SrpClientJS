import {SRPClientContext} from './srp';
import {hexToBase64} from './sha';

//----------------------
/**
 * На входе - массив байт, закодированный в виде Base64
 * На выходе - HEX-строка, представляющаю тот же массов байт
 */
function base64toHex(s) {
    var hex_chr = "0123456789ABCDEF";
    var hex = "";
    var bytes = atob(s);
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes.charCodeAt(i);
        hex += hex_chr.charAt((b >>> 4) & 0x0f);
        hex += hex_chr.charAt(b & 0x0f);
    }
    return hex;
}

/**
 * На входе - SOAP-response со стадии preLogin. Пример входных данных:
 * <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 * <soap:Body>
 * <preLoginResponse xmlns="http://upg.sbns.bssys.com/">
 * <return>tDVQd3iR7QCWbA==</return>
 * <return>jn69339pqDyhey1AE6EVxG/GeYwj/B8iMFQduB5TbJs=</return>
 * <return>XWnDCCqXMzvqSA==</return>
 * <return>MThlZWU5YjAtODE5Zi00MjIwLThkYjYtNzE3ZjM1NDY1Mjll</return>
 * <return>MTcxMzg2MjQ0NA==</return>
 * </preLoginResponse>
 * </soap:Body>
 * </soap:Envelope>
 *
 * На выходе - те же входные данные, но в виде массива.
 */
function parseResponse(response) {
    var startTag = "<return>";
    var endTag = "</return>";
    var data = [];
    for (var i = 0; i < 5; i++) {
        data[data.length] = response.substring(response.indexOf(startTag) + startTag.length,
            response.indexOf(endTag));
        response = response.substring(response.indexOf(endTag) + endTag.length);
    }
    return data;
}

/**
* Формирует SOAP-request для стадии Login.
* На входе - готовые данные для стадии Login.
* На выходе - SOAP-request. Пример выходных данных:
* <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:upg="http://
upg.sbns.bssys.com/">
* <soapenv:Header/>
* <soapenv:Body>
* <upg:login>
* <upg:userLogin>transport</upg:userLogin>
* <upg:preloginId>18eee9b0-819f-4220-8db6-717f3546529e</upg:preloginId>
* <upg:clientAuthData>IiN+agBcd4tU/FofTnoQph7NhvU=</upg:clientAuthData>
* <upg:clientAuthData>9fstMnBdN38SCirOYwI8Uxyyu+VQEWEZdlQO46Ol5n0=</upg:clientAuthData>
* </upg:login>
* </soapenv:Body>
* </soapenv:Envelope>
*/
function formLoginRequest(login, preloginId, passwordHash, extPasswordData) {
    var s = '\
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:upg="http://upg.sbns.bssys.com/">\n\
    <soapenv:Header/>\n\
    <soapenv:Body>\n\
    <upg:login>\n\
    <upg:userLogin>%s</upg:userLogin>\n\
    <upg:preloginId>%s</upg:preloginId>\n\
    <upg:clientAuthData>%s</upg:clientAuthData>\n\
    <upg:clientAuthData>%s</upg:clientAuthData>\n\
    </upg:login>\n\
    </soapenv:Body>\n\
    </soapenv:Envelope>';
    var args = [].slice.call(arguments, 0);
    var i = 0;
    return s.replace(/%s/g, function () {
        return args[i++];
    });
}

/**
 * Аутентификация с использованием SRP версии 6a.
 * @param login - логин транспортной учетной записи
 * @param password - пароль транспортной учетной записи
 * @param response - SOAP-response со стадии preLogin
 */
function upgPreloginSrp(login, password, response) {
    var data = parseResponse(response);
    var salt = base64toHex(data[0]); // данные для инициализации SRP
    var bytesFromServer = base64toHex(data[1]); // данные для инициализации SRP
    var preloginId = atob(data[3]); // ID сессии
    var userHash = atob(data[4]); // хеш идентификатора пользователя
    var srpClient = new SRPClientContext(salt, bytesFromServer);
    var passwordHash = hexToBase64(srpClient.makeAuthorizationData(userHash, password));
    var extPasswordData = hexToBase64(srpClient.getAbytes());
    return formLoginRequest(login, preloginId, passwordHash, extPasswordData);
}

export {upgPreloginSrp};