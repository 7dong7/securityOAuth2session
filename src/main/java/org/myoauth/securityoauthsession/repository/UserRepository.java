package org.myoauth.securityoauthsession.repository;

import org.myoauth.securityoauthsession.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<UserEntity, Long> {


    // 사용자 조회
    UserEntity findByUsername(String username);
}
