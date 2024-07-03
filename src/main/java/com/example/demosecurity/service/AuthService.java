package com.example.demosecurity.service;

import com.example.demosecurity.entity.Role;
import com.example.demosecurity.entity.User;
import com.example.demosecurity.exception.BadRequestException;
import com.example.demosecurity.model.request.LoginRequest;
import com.example.demosecurity.model.request.RegisterRequest;
import com.example.demosecurity.repository.RoleRepository;
import com.example.demosecurity.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final HttpSession session;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public void login(LoginRequest request) {
        // Tạo đối tượng xác thực
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
        );

        try {
            // Tiến hành xác thực
            Authentication authentication = authenticationManager.authenticate(token);

            // Lưu đối tượng đã xác thực vào trong SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Lưu vào trong session
            session.setAttribute("MY_SESSION", authentication.getName()); // Lưu email -> session
        } catch (AuthenticationException e) {
            throw new BadRequestException("Tài khoản hoặc mật khẩu không đúng");
        }
    }
    public void register(RegisterRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent()) {
            throw new BadRequestException("Email da ton tai!");
        }
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new BadRequestException("Khong co Role nay!"));
        User newUser = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(List.of(userRole))
                .build();
        userRepository.save(newUser);
    }
}
