package com.pn.controller;

import com.pn.entity.LoginUser;
import com.pn.entity.Result;
import com.pn.entity.User;
import com.pn.service.UserService;
import com.pn.utils.CurrentUser;
import com.pn.utils.DigestUtil;
import com.pn.utils.TokenUtils;
import com.pn.utils.WarehouseConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {


    @Autowired
    private UserService userService;


    @Autowired
    private StringRedisTemplate stringRedisTemplate;


    @Autowired
    private TokenUtils tokenUtils;


    @PostMapping("/login")
    public Result login(@RequestBody LoginUser loginUser){

        if(!stringRedisTemplate.hasKey(loginUser.getVerificationCode())){
            return Result.err(Result.CODE_ERR_BUSINESS,"验证码不正确!");
        }

        User user = userService.findUserByCode(loginUser.getUserCode());

        if(user != null){

            if(user.getUserState().equals(WarehouseConstants.USER_STATE_PASS)){

                String password = DigestUtil.hmacSign(loginUser.getUserPwd());

                if(password.equals(user.getUserPwd())){

                    CurrentUser currentUser = new CurrentUser(user.getUserId(),user.getUserCode(),user.getUserName());

                    String token = tokenUtils.loginSign(currentUser,user.getUserPwd());
                    //返回
                    return Result.ok("登录成功!",token);
                } else {

                    return Result.err(Result.CODE_ERR_BUSINESS,"密码不一致!");
                }
            } else {
                //查询到的用户状态是未审核的状态
                return Result.err(Result.CODE_ERR_BUSINESS,"用户未审核!");
            }
        } else {
            //没有查询到用户
            return Result.err(Result.CODE_ERR_BUSINESS,"该用户不存在!");
        }
    }


    @GetMapping("/curr-user")
    public Result currUser(@RequestHeader(WarehouseConstants.HEADER_TOKEN_NAME) String clientToken){
        //获取到当前登录的用户
        CurrentUser currentUser = tokenUtils.getCurrentUser(clientToken);
        //响应
        return Result.ok(currentUser);
    }


    @DeleteMapping("/logout")
    public Result logout(@RequestHeader(WarehouseConstants.HEADER_TOKEN_NAME) String clientToken){
        //从redis中移除token的键
        stringRedisTemplate.delete(clientToken);
        return Result.ok();
    }

}

