package dev.project.airline.airport;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.project.airline.user.User;
import dev.project.airline.user.UserService;

@RestController
@RequestMapping("/api/v1")
public class airportController {

    private final UserService userService;

    public airportController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/airport")
    public String getAirport() {
        return "List of Airports";
    }

    @GetMapping("/users")
    public  User Users() {
        return userService.findAll();
    }

    @GetMapping("/public")
    public String getPublic() {
        return "Public API";
    }

    @GetMapping("/private")
    public String getPrivate() {
        return "Private API";
    }
}
