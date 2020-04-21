package cn.enilu.flash.security;

import cn.enilu.flash.bean.vo.front.Rets;
import cn.enilu.flash.cache.TokenCache;
import cn.enilu.flash.utils.HttpUtil;

import com.alibaba.fastjson.JSON;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author ：enilu
 * @date ：Created in 11/19/2019 2:28 PM
 */
@Component
public class SystemLogoutFilter extends LogoutFilter {
    private static final Logger logger = LoggerFactory.getLogger(SystemLogoutFilter.class);

    @Autowired
    private TokenCache tokenCache;

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        try {
            subject.logout();
            String token = HttpUtil.getToken();
            if(token != null){
                tokenCache.remove(token);
                tokenCache.removeAuthz(token);
            }
        } catch (Exception ex) {
            logger.error("退出登录错误",ex);
        }

        this.writeResult(response);
        //不执行后续的过滤器
        return false;
    }

    private void writeResult(ServletResponse response){
        //响应Json结果
        PrintWriter out = null;
        try {
            out = response.getWriter();
            out.append(JSON.toJSONString(Rets.success()));
        } catch (IOException e) {
            logger.error("返回Response信息出现IOException异常:" + e.getMessage());
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
}
