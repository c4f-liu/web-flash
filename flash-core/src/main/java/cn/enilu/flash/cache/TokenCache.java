package cn.enilu.flash.cache;

import cn.enilu.flash.bean.core.ShiroUser;
import cn.enilu.flash.bean.entity.system.User;
import cn.enilu.flash.utils.HttpUtil;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 用户登录时，生成的Token与用户ID的对应关系
 */
@Service
public   class TokenCache {

    @Autowired
    private CacheDao cacheDao;

    public   void put(String token, Long idUser) {
        cacheDao.hset(CacheDao.SESSION,token, idUser);
    }

    public   Long get(String token) {
        return cacheDao.hget(CacheDao.SESSION,token,Long.class);
    }

    public   void remove(String token) {
        cacheDao.hdel(CacheDao.SESSION,token);
    }

    public void setUser(String username, User shiroUser){
        cacheDao.hset(CacheDao.SESSION,username+"user",shiroUser);
    }
    public User getUser(String username){
        return cacheDao.hget(CacheDao.SESSION,username+"user",User.class);
    }

    public   void removeUser(String username) {
        cacheDao.hdel(CacheDao.SESSION,username+"user");
    }    

    public void putAuthz(String username, SimpleAuthorizationInfo authz){
        cacheDao.hset(CacheDao.SESSION,username+"authz",authz);
    }

    public SimpleAuthorizationInfo getAuthz(String username){
        return cacheDao.hget(CacheDao.SESSION, username+"authz", SimpleAuthorizationInfo.class);
    }

    public   void removeAuthz(String username) {
        cacheDao.hdel(CacheDao.SESSION,username+"authz");
    }
}
