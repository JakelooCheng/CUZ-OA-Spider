const cheerio = require("cheerio")
let request = require("request")
const RSA = require('./security.js')
const qs = require("qs");

// 配置全局的 Cookie
let COOKIE_JAR = request.jar()
request = request.defaults({jar: COOKIE_JAR})

// 入口函数
// doLogin("<学号>", "<密码>")

function doLogin(user_id, password) {
    let execution = ""
    getExecution().then(data => {
        execution = data
        return getEncryptedPassword(password)
    }).then(data => {
        return postLogin(user_id, data, execution)
    }).then(data => {
        return getWebVpn(data)
    }).then(() => {
        console.log(COOKIE_JAR['_jar']['store']['idx']['cuz.edu.cn']['/'])
        console.log(COOKIE_JAR['_jar']['store']['idx']['cuz.edu.cn']['/']['web_vpn_user_token'])
        // 返回的 Cookie
    }).catch(error => {
        console.log(error)
    })
}

/**
 * 获取门户网站 Execution
 * 此数值用于提交，需要从网页爬取，换取时会拿到 COOKIE SESSION 用于后续操作
 * @return Promise 换取的Execution
 */
function getExecution() {
    return new Promise((resolve, reject) => {
        request({
            url: 'https://sso.casb.cuz.edu.cn/cas/login',
            method: "GET",
        }, (error, response, body) => {
            if (!error && response.statusCode === 200) {
                const $ = cheerio.load(body)
                let execution = $("input[name='execution']").val()
                resolve(execution)
            } else {
                reject(String(error))
            }
        });
    })
}

/**
 * 获取加密后的密码
 * 基于 security.js 的 RSA 加密方式
 * 使用 Cookie 换取公钥 => security.js 生成私钥 => 使用私钥加密密码
 * @param password 原始密码
 * @return Promise 加密后的密码
 */
function getEncryptedPassword(password) {
    return new Promise((resolve, reject) => {
        request({
            url: 'https://sso.casb.cuz.edu.cn/cas/v2/getPubKey',
            method: "GET",
        }, (error, response, body) => {
            if (!error && response.statusCode === 200) {
                const DATA = JSON.parse(body)
                const EXPONENT = DATA.exponent
                const MODULUS = DATA.modulus
                resolve(RSA.getPassword(password, MODULUS, EXPONENT))
            } else {
                reject(String(error))
            }
        });
    })
}

/**
 * 请求登录
 * @param user_id 学号信息
 * @param encryptedPassword 加密后的密码
 * @param execution 门户网站 Execution 字段
 * @return Promise 重定向网站
 */
function postLogin(user_id, encryptedPassword, execution) {
    return new Promise((resolve, reject) => {
        const DATA = qs.stringify({
            'username':user_id,
            'password':encryptedPassword,
            'mobile':"",
            'authcode':"",
            'execution': execution,
            '_eventId': "submit"
        })
        request({
            url: "https://sso.casb.cuz.edu.cn/cas/login?service=http://portal1.cuz.edu.cn:8800%2foauth%2fauthorize%3fresponse_type%3dcode%26client_id%3dINTERNAL00001%26redirect_uri%3dhttp:%252f%252fehall.cuz.edu.cn:8888%252f%26scope%3dapi_base%26state%3d1",
            method: "POST",
            headers: {
                "content-type": "application/x-www-form-urlencoded",
                "Host": "sso.casb.cuz.edu.cn",
                "Origin": "https://sso.casb.cuz.edu.cn",
                "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Microsoft Edge\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.1150.55"
            },
            followRedirect:true,
            body: DATA,
        }, (error, response, body) => {
            if (!error && response.statusCode === 302) {
                const TICKET = response.headers['location'].split("=")[1]
                const LOCATION = "https://portal.casb.cuz.edu.cn/oauth/authorize?response_type=code&client_id=INTERNAL00001&redirect_uri=http:%2f%2fehall.cuz.edu.cn:8888%2f&scope=api_base&state=1&ticket=" + TICKET
                resolve(LOCATION)
            } else {
                reject(String(error))
            }
        });
    })
}

/**
 * 请求通用 Cookie web_vpn
 * OA 需要该字段进行跟踪，登录换回的 iPlate 仅能获取个人信息，无法访问内网
 * @param location 重定向解析网站地址
 * @return Promise
 */
function getWebVpn(location) {
    return new Promise((resolve, reject) => {
        request({
            url: location,
            method: "GET",
            followRedirect:true,
        }, function(error, response, body) {
            if (!error && response.statusCode === 200) {
                resolve()
            } else {
                reject(String(error))
            }
        });
    })
}