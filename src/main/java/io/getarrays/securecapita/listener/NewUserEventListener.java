package io.getarrays.securecapita.listener;

import io.getarrays.securecapita.event.NewUserEvent;
import io.getarrays.securecapita.service.EventService;
import io.getarrays.securecapita.utils.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 Class that automatically calls onNewUserEvent () every time when NewUserEvent is created
 */
@Component
@RequiredArgsConstructor
public class NewUserEventListener
{
    private final EventService eventService;
    private final HttpServletRequest request;
    @EventListener
    public void onNewUserEvent (NewUserEvent event)
    {
        eventService.addUserEvent (event.getEmail (),
                                   event.getType (),
                                   RequestUtils.getDevice (request),
                                   RequestUtils.getIpAddress (request)
                                  );
    }
}
