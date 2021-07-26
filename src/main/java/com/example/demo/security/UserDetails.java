package com.example.demo.security;

import com.example.demo.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

public class UserDetails implements org.springframework.security.core.userdetails.UserDetails {

    private User myEntity;

    public UserDetails(User myEntity) {
        this.myEntity = myEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.asList(new SimpleGrantedAuthority(myEntity.getRole().toLowerCase()));
    }

    @Override
    public String getPassword() {
        return myEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return myEntity.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return myEntity.isEnabled();
    }

    @Override
    public boolean isAccountNonLocked() {
        return myEntity.isEnabled();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return myEntity.isEnabled();
    }

    @Override
    public boolean isEnabled() {
        return myEntity.isEnabled();
    }
}
