from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import IntegrityError

from authentication.permissions import (
    HasModulePermission,
    IsAuthenticatedAndOrgMember,
    IsOrgAdmin,
    get_user_org_id,
)
from authentication.models import Organization

from .models import Target, Endpoint
from .serializers import TargetSerializer, EndpointSerializer



class TargetViewSet(viewsets.ModelViewSet):
    serializer_class = TargetSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "trigger_scan"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return Target.objects.select_related('user').filter(org_id=org_id)

    def perform_create(self, serializer):
        org_id = get_user_org_id(self.request)
        serializer.save(user=self.request.user, org_id=org_id)


class EndpointViewSet(viewsets.ModelViewSet):
    serializer_class = EndpointSerializer
    permission_classes = [permissions.IsAuthenticated, IsAuthenticatedAndOrgMember, HasModulePermission]
    required_module = "endpoints"

    def get_queryset(self):
        org_id = get_user_org_id(self.request)
        return Endpoint.objects.select_related('target').filter(target__org_id=org_id)


# ─── Admin: Domain Management (Org-scoped CRUD) ──────────────────────────────

class AdminDomainListView(APIView):
    """
    List all domains for a given organization (admin only).
    """
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request, org_id):
        # Verify admin access to this org
        if request.user.is_superuser:
            try:
                Organization.objects.get(org_id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=404)
        else:
            if not request.user.memberships.filter(
                organization__org_id=org_id, role="admin"
            ).exists():
                return Response({"error": "Not authorized"}, status=403)

        domains = Target.objects.filter(org_id=org_id).select_related('user')
        data = []
        for t in domains:
            data.append({
                "id": t.id,
                "domain": t.domain,
                "description": t.description,
                "added_by": t.user.username,
                "added_on": t.added_on,
                "last_scanned": t.last_scanned,
            })
        return Response(data)

    def post(self, request, org_id):
        """Add a domain to the organization."""
        # Verify admin access
        if request.user.is_superuser:
            try:
                org = Organization.objects.get(org_id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=404)
        else:
            membership = request.user.memberships.filter(
                organization__org_id=org_id, role="admin"
            ).first()
            if not membership:
                return Response({"error": "Not authorized"}, status=403)
            org = membership.organization

        domain = request.data.get("domain", "").strip()
        description = request.data.get("description", "").strip()

        if not domain:
            return Response({"error": "Domain is required"}, status=400)

        try:
            target = Target.objects.create(
                user=request.user,
                org_id=org.org_id,
                domain=domain.lower(),
                description=description,
            )
            return Response({
                "message": "Domain added successfully",
                "domain": {
                    "id": target.id,
                    "domain": target.domain,
                    "description": target.description,
                    "added_on": target.added_on,
                },
            }, status=201)
        except IntegrityError:
            return Response({"error": "Domain already exists"}, status=409)


class AdminDomainDetailView(APIView):
    """
    Update or delete a specific domain (admin only).
    """
    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def patch(self, request, org_id, domain_id):
        if request.user.is_superuser:
            target = Target.objects.filter(id=domain_id, org_id=org_id).first()
        else:
            target = Target.objects.filter(
                id=domain_id, org_id=org_id,
                user__memberships__organization__org_id=org_id,
                user__memberships__role="admin",
            ).first()

        if not target:
            return Response({"error": "Domain not found"}, status=404)

        description = request.data.get("description")
        if description is not None:
            target.description = description.strip()
        if "domain" in request.data:
            domain = request.data.get("domain", "").strip()
            if domain:
                try:
                    Target.objects.filter(id=target.id).exclude(domain=target.domain).update(domain=domain.lower())
                    target.domain = domain.lower()
                except IntegrityError:
                    return Response({"error": "Domain already exists"}, status=409)
        target.save()

        return Response({
            "message": "Domain updated successfully",
            "domain": {
                "id": target.id,
                "domain": target.domain,
                "description": target.description,
            },
        })

    def delete(self, request, org_id, domain_id):
        if request.user.is_superuser:
            target = Target.objects.filter(id=domain_id, org_id=org_id).first()
        else:
            target = Target.objects.filter(
                id=domain_id, org_id=org_id,
                user__memberships__organization__org_id=org_id,
                user__memberships__role="admin",
            ).first()

        if not target:
            return Response({"error": "Domain not found"}, status=404)

        target.delete()
        return Response({"message": "Domain deleted successfully"})
