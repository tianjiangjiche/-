package com.pn.filter;

import com.alibaba.fastjson.JSON;
import com.pn.entity.Result;
import com.pn.utils.WarehouseConstants;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class SecurityFilter implements Filter {

    private StringRedisTemplate stringRedisTemplate;
    //生成redis模块的set方法
    public void setStringRedisTemplate(StringRedisTemplate stringRedisTemplate){
        this.stringRedisTemplate = stringRedisTemplate;
    }

    /**
     *
     * @param servletRequest
     * @param servletResponse
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        //请求
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        //响应
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        //获取请求的url接口
        String path = request.getServletPath();
        /**
         * 白名单请求直接放行
         */
        List<String> urlList = new ArrayList<>();
        //验证码需要设置成白名单请求
        urlList.add("/captcha/captchaImage");
        //登录需要设置成白名单请求
        urlList.add("/login");
        //退出需要设置成白名单请求
        urlList.add("/logout");
        //如果包含，则说明是白名单请求
        if (urlList.contains(path)){
            //递归
            filterChain.doFilter((ServletRequest) request, (ServletResponse) response);
            //中止函数
            return;
        }
        /**
         * 其他请求都需要校验是否携带了token，以及判断redis中是否存在token的键
         */
        String clientToken = request.getHeader(WarehouseConstants.HEADER_TOKEN_NAME);
        //对token进行校验，如果通过则请求放行
        if (StringUtils.hasText(clientToken) && stringRedisTemplate.hasKey(clientToken)){
            //递归
            filterChain.doFilter((ServletRequest) request, (ServletResponse) response);
            //中止函数
            return;
        }
        //校验失败(未登录&&token过期)
        Result result = Result.err(Result.CODE_ERR_UNLOGINED,"请登录");
        //将对象转换成json字符串
        String jsonStr = JSON.toJSONString(result);
        //设置响应的正文
        response.setContentType("application/json;charset=UTF-8");
        //使用流输出
        PrintWriter out = response.getWriter();
        out.println(jsonStr);
        out.flush();
        out.close();

    }
}
