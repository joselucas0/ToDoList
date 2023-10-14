package br.com.joselucas.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.joselucas.todolist.user.iUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{


    @Autowired
    private iUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


                var authorization  = request.getHeader("Authorization");
                var authEncoded = authorization.substring("Basic".length()).trim();

                byte[] authDecode = Base64.getDecoder().decode(authEncoded);
                var authString = new String(authDecode);
                String[] credentials = authString.split(":");
                String username = credentials[0];
                String passoword = credentials[1];
                

                var user = this.userRepository.findByUsername(username);
                if(user == null){
                    response.sendError(401);
                }else{
                    var passworedVerify = BCrypt.verifyer().verify(passoword.toCharArray(), user.getPassword());
                    if(passworedVerify.verified){
                        filterChain.doFilter(request, response);
                    }else{
                        response.sendError(401);
                    }
                }


                
    }

   
    
}
